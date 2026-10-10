//! Bounded UDP fixture for separate responses; not a production CoAP transport.
//!
//! At most eight admitted requests and eight complete responses are retained.
//! Oversized input and admission exhaustion are dropped before acknowledgement.
//! Response queue pressure waits within admission bounds; an oversized response
//! terminates this listener instead of truncating.
//! This fixture does not qualify lost-response retransmission or DTLS.

use async_trait::async_trait;
use coap::server::{Listener, Responder, TransportRequestSender};
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const MAX_DATAGRAM: usize = 2048;
const MAX_PENDING: usize = 8;
type Reply = io::Result<(Vec<u8>, SocketAddr)>;

pub struct SeparateListener {
    socket: tokio::net::UdpSocket,
    response_rx: mpsc::Receiver<Reply>,
    response_tx: mpsc::Sender<Reply>,
    admission: Arc<Semaphore>,
}

impl SeparateListener {
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(address).await?;
        let (response_tx, response_rx) = mpsc::channel(MAX_PENDING);
        Ok(Self {
            socket,
            response_rx,
            response_tx,
            admission: Arc::new(Semaphore::new(MAX_PENDING)),
        })
    }
}

struct SeparateResponder {
    address: SocketAddr,
    tx: mpsc::Sender<Reply>,
    // Retained until the backend releases this request, bounding its ingress.
    _permit: OwnedSemaphorePermit,
}

#[async_trait]
impl Responder for SeparateResponder {
    async fn respond(&self, response: Vec<u8>) {
        let reply = if response.len() <= MAX_DATAGRAM {
            Ok((response, self.address))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture response exceeds 2048 bytes",
            ))
        };
        // Backpressure retains one bounded response per admitted backend task.
        // A closed listener cannot accept or silently truncate this response.
        let _ = self.tx.send(reply).await;
    }
    fn address(&self) -> SocketAddr {
        self.address
    }
}

async fn send_complete(
    socket: &tokio::net::UdpSocket,
    bytes: &[u8],
    peer: SocketAddr,
) -> io::Result<()> {
    if socket.send_to(bytes, peer).await? != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial fixture datagram",
        ));
    }
    Ok(())
}

#[async_trait]
impl Listener for SeparateListener {
    async fn listen(
        mut self: Box<Self>,
        sender: TransportRequestSender,
    ) -> io::Result<tokio::task::JoinHandle<io::Result<()>>> {
        Ok(tokio::spawn(async move {
            // Sentinel byte prevents treating a truncated large datagram as valid.
            let mut buffer = [0u8; MAX_DATAGRAM + 1];
            loop {
                tokio::select! {
                    datagram = self.socket.recv_from(&mut buffer) => {
                        let (size, source) = match datagram {
                            // Winsock consumes the oversized UDP datagram and
                            // reports WSAEMSGSIZE instead of the sentinel length.
                            #[cfg(windows)]
                            Err(error) if error.raw_os_error() == Some(10040) => continue,
                            other => other?,
                        };
                        if size > MAX_DATAGRAM { continue; }
                        let Ok(packet) = Packet::from_bytes(&buffer[..size]) else { continue; };
                        // Empty ACK/RST messages do not occupy backend request slots.
                        if !matches!(packet.header.code, MessageClass::Request(_)) { continue; }
                        let Ok(permit) = Arc::clone(&self.admission).try_acquire_owned() else { continue; };
                        let separate = packet.get_option(CoapOption::UriPath)
                            .is_some_and(|parts| parts.len() == 1 && parts.front().is_some_and(|path| path == b"separate"));
                        if separate && packet.header.get_type() == MessageType::Confirmable
                            && packet.header.code == MessageClass::Request(RequestType::Get) {
                            let mid = packet.header.message_id.to_be_bytes();
                            send_complete(&self.socket, &[0x60, 0, mid[0], mid[1]], source).await?;
                        }
                        sender.send((buffer[..size].to_vec(), Arc::new(SeparateResponder {
                            address: source, tx: self.response_tx.clone(), _permit: permit,
                        }))).map_err(|_| io::Error::other("server receiver closed"))?;
                    }
                    response = self.response_rx.recv() => {
                        let Some(reply) = response else { return Ok(()) };
                        let (bytes, destination) = reply?;
                        send_complete(&self.socket, &bytes, destination).await?;
                    }
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn response_bounds_and_admission_are_released_by_owner() {
        let listener = SeparateListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut permits = Vec::new();
        for _ in 0..MAX_PENDING {
            permits.push(Arc::clone(&listener.admission).try_acquire_owned().unwrap());
        }
        assert!(Arc::clone(&listener.admission).try_acquire_owned().is_err());
        drop(permits.pop());
        let permit = Arc::clone(&listener.admission).try_acquire_owned().unwrap();
        let (tx, mut rx) = mpsc::channel(MAX_PENDING);
        let responder = SeparateResponder {
            address: listener.socket.local_addr().unwrap(),
            tx,
            _permit: permit,
        };
        responder.respond(vec![7; MAX_DATAGRAM]).await;
        assert_eq!(rx.recv().await.unwrap().unwrap().0, vec![7; MAX_DATAGRAM]);
        responder.respond(vec![7; MAX_DATAGRAM + 1]).await;
        assert_eq!(
            rx.recv().await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(responder);
        assert!(Arc::clone(&listener.admission).try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn oversized_and_saturated_input_never_acknowledges_then_recovers() {
        let listener = SeparateListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.socket.local_addr().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = Box::new(listener).listen(tx).await.unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = Packet::new();
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Get);
        packet.add_option(CoapOption::UriPath, b"separate".to_vec());
        packet.payload = vec![1; MAX_DATAGRAM];
        let large = packet.to_bytes_with_limit(MAX_DATAGRAM + 100).unwrap();
        socket.send_to(&large, address).await.unwrap();
        let mut buffer = [0; MAX_DATAGRAM];
        assert!(
            timeout(Duration::from_millis(30), socket.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert!(rx.try_recv().is_err());
        packet.payload.clear();
        let mut owners = Vec::new();
        for mid in 0..MAX_PENDING {
            packet.header.message_id = mid as u16;
            socket
                .send_to(&packet.to_bytes().unwrap(), address)
                .await
                .unwrap();
            let (size, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..size], &[0x60, 0, 0, mid as u8]);
            owners.push(
                timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        socket
            .send_to(&packet.to_bytes().unwrap(), address)
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(30), socket.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert!(rx.try_recv().is_err());
        drop(owners.pop());
        packet.header.message_id = 100;
        socket
            .send_to(&packet.to_bytes().unwrap(), address)
            .await
            .unwrap();
        let (size, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], &[0x60, 0, 0, 100]);
        let (_, owner) = rx.recv().await.unwrap();
        owner.respond(vec![7; MAX_DATAGRAM + 1]).await;
        assert_eq!(
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
