//! Bounded recovery of an intact peer final-flight retransmission.
//! This retains the already generated packets; it does not generate or verify
//! cryptographic handshake messages. Incoming records pass the reader's normal
//! authentication and replay checks before reaching this owner.

use std::io::Cursor;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::{Duration, Instant};

use super::PacketSendRequest;
use crate::flight::Packet;
use crate::handshake::handshake_header::{HandshakeHeader, HANDSHAKE_HEADER_LENGTH};
use crate::handshake::HandshakeType;

// RFC 6347 section 4.2.4: at least twice RFC 793's two-minute default MSL.
const RETENTION: Duration = Duration::from_secs(240);
const INITIAL_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(60);
const FINISHED_LEN: usize = 12;

#[derive(Clone, Default)]
pub(crate) struct FinalFlightHandle {
    state: Arc<Mutex<Option<FinalFlight>>>,
    pub(crate) changed: Arc<Notify>,
}

struct FinalFlight {
    epoch: u16,
    sequence: u16,
    expected: [u8; FINISHED_LEN],
    covered: u16,
    packets: Option<Vec<Packet>>,
    expires: Instant,
    next_retry: Instant,
    interval: Duration,
    pending: bool,
}

impl FinalFlightHandle {
    pub(crate) fn start(
        &self,
        writer: Arc<mpsc::Sender<PacketSendRequest>>,
    ) -> tokio::task::JoinHandle<()> {
        let owner = self.clone();
        tokio::spawn(async move { owner.run(writer).await })
    }

    async fn run(self, writer: Arc<mpsc::Sender<PacketSendRequest>>) {
        // This finite task never cancels the generic connection's recv future.
        // The fixed deadline bounds queue handoff, not scheduling of socket
        // writes already admitted by the existing connection writer.
        while let Some(deadline) = self.deadline().await {
            if Instant::now() < deadline {
                tokio::select! {
                    _ = self.changed.notified() => continue,
                    _ = tokio::time::sleep_until(deadline) => {}
                }
            }
            let Some(packets) = self.due(Instant::now()).await else {
                continue;
            };
            // A full writer queue must not extend packet retention or delay
            // close. Reserve without moving the packet clone into a pending
            // send, then recheck ownership while holding the state lock.
            loop {
                let expiry = {
                    let guard = self.state.lock().await;
                    let Some(state) = guard.as_ref() else {
                        return;
                    };
                    if state.packets.is_none() {
                        return;
                    }
                    state.expires
                };
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(expiry) => {
                        if let Some(state) = self.state.lock().await.as_mut() {
                            state.expire(Instant::now());
                        }
                        return;
                    }
                    _ = self.changed.notified() => continue,
                    permit = writer.reserve() => {
                        let Ok(permit) = permit else {
                            self.clear().await;
                            return;
                        };
                        let mut guard = self.state.lock().await;
                        let Some(state) = guard.as_mut() else { return; };
                        state.expire(Instant::now());
                        if state.packets.is_none() { return; }
                        permit.send((packets, None));
                        break;
                    }
                }
            }
        }
    }

    pub(crate) async fn install(
        &self,
        epoch: u16,
        sequence: u16,
        expected: [u8; FINISHED_LEN],
        mut packets: Vec<Packet>,
    ) {
        // Retransmission shares the connection writer's monotonic record IDs.
        for packet in &mut packets {
            packet.reset_local_sequence_number = false;
        }
        let now = Instant::now();
        *self.state.lock().await = Some(FinalFlight {
            epoch,
            sequence,
            expected,
            covered: 0,
            packets: Some(packets),
            expires: now + RETENTION,
            next_retry: now + INITIAL_RETRY,
            interval: INITIAL_RETRY,
            pending: false,
        });
        self.changed.notify_one();
    }

    pub(crate) async fn deadline(&self) -> Option<Instant> {
        self.state.lock().await.as_ref().and_then(|state| {
            state.packets.as_ref()?;
            Some(if state.pending {
                state.expires.min(state.next_retry)
            } else {
                state.expires
            })
        })
    }

    pub(crate) async fn due(&self, now: Instant) -> Option<Vec<Packet>> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut()?;
        state.expire(now);
        if !state.pending || now < state.next_retry {
            return None;
        }
        let packets = state.packets.as_ref()?.clone();
        state.pending = false;
        state.covered = 0;
        state.interval = (state.interval * 2).min(MAX_RETRY);
        state.next_retry = now + state.interval;
        Some(packets)
    }

    /// Consume well-formed records consisting only of this connection's old
    /// Finished fragments, including after expiry. Malformed/mixed records and
    /// other epochs/messages retain the upstream reader behavior.
    pub(crate) async fn receive(&self, epoch: u16, payload: &[u8], now: Instant) -> bool {
        let mut guard = self.state.lock().await;
        let Some(state) = guard.as_mut() else {
            return false;
        };
        if epoch != state.epoch || !state.matches_identity(payload) {
            return false;
        }
        state.expire(now);
        if state.packets.is_none() {
            return true;
        }
        let mut remaining = payload;
        while !remaining.is_empty() {
            // The identity pass has checked every length and offset.
            let header = HandshakeHeader::unmarshal(&mut Cursor::new(remaining)).unwrap();
            let offset = header.fragment_offset as usize;
            let len = header.fragment_length as usize;
            let end = HANDSHAKE_HEADER_LENGTH + len;
            if remaining[HANDSHAKE_HEADER_LENGTH..end] != state.expected[offset..offset + len] {
                state.covered = 0;
                return true;
            }
            for index in offset..offset + len {
                state.covered |= 1 << index;
            }
            remaining = &remaining[end..];
        }
        if state.covered == (1 << FINISHED_LEN) - 1 {
            state.pending = true;
            state.covered = 0;
            self.changed.notify_one();
        }
        true
    }

    pub(crate) async fn clear(&self) {
        self.state.lock().await.take();
        self.changed.notify_one();
    }
}

impl FinalFlight {
    fn expire(&mut self, now: Instant) {
        if now >= self.expires {
            self.packets = None;
            self.expected.fill(0);
            self.covered = 0;
            self.pending = false;
        }
    }

    fn matches_identity(&self, mut payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        while !payload.is_empty() {
            let Ok(header) = HandshakeHeader::unmarshal(&mut Cursor::new(payload)) else {
                return false;
            };
            let offset = header.fragment_offset as usize;
            let len = header.fragment_length as usize;
            if header.handshake_type != HandshakeType::Finished
                || header.message_sequence != self.sequence
                || header.length as usize != FINISHED_LEN
                || len == 0
                || offset > FINISHED_LEN
                || len > FINISHED_LEN - offset
                || HANDSHAKE_HEADER_LENGTH + len > payload.len()
            {
                return false;
            }
            payload = &payload[HANDSHAKE_HEADER_LENGTH + len..];
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // State-machine inputs only: no socket, cipher or peer is involved here.
    fn fragment(sequence: u16, offset: usize, bytes: &[u8]) -> Vec<u8> {
        let header = HandshakeHeader {
            handshake_type: HandshakeType::Finished,
            length: FINISHED_LEN as u32,
            message_sequence: sequence,
            fragment_offset: offset as u32,
            fragment_length: bytes.len() as u32,
        };
        let mut out = Vec::new();
        header.marshal(&mut out).unwrap();
        out.extend_from_slice(bytes);
        out
    }

    #[tokio::test]
    async fn partial_retry_never_moves_retention_or_sends_before_rate_deadline() {
        let handle = FinalFlightHandle::default();
        handle.install(1, 4, [7; 12], Vec::new()).await;
        let (expiry, first) = {
            let guard = handle.state.lock().await;
            let state = guard.as_ref().unwrap();
            (state.expires, state.next_retry)
        };
        let now = first - INITIAL_RETRY;
        assert!(handle.receive(1, &fragment(4, 6, &[7; 6]), now).await);
        assert_eq!(handle.deadline().await, Some(expiry));
        assert!(handle.due(first).await.is_none());
        assert!(handle.receive(1, &fragment(4, 0, &[7; 6]), now).await);
        assert_eq!(handle.deadline().await, Some(first));
        assert!(handle.due(first - Duration::from_nanos(1)).await.is_none());
        assert!(handle.due(first).await.is_some());
        assert!(handle.due(first).await.is_none());
        assert_eq!(handle.state.lock().await.as_ref().unwrap().expires, expiry);
    }

    #[tokio::test]
    async fn repeated_complete_retries_coalesce_and_back_off_without_extending_expiry() {
        let handle = FinalFlightHandle::default();
        handle.install(1, 4, [7; 12], Vec::new()).await;
        let expiry = handle.state.lock().await.as_ref().unwrap().expires;
        for _ in 0..7 {
            let at = handle.state.lock().await.as_ref().unwrap().next_retry;
            for _ in 0..32 {
                assert!(handle.receive(1, &fragment(4, 0, &[7; 12]), at).await);
            }
            assert!(handle.due(at).await.is_some());
            assert!(handle.due(at).await.is_none());
            let state = handle.state.lock().await;
            let state = state.as_ref().unwrap();
            assert_eq!(state.expires, expiry);
            assert!(state.interval <= MAX_RETRY);
        }
        assert_eq!(
            handle.state.lock().await.as_ref().unwrap().interval,
            MAX_RETRY
        );
    }

    #[tokio::test]
    async fn expiry_clears_packets_and_bytes_but_filters_only_the_old_identity() {
        let handle = FinalFlightHandle::default();
        handle.install(1, 4, [7; 12], Vec::new()).await;
        let expiry = handle.state.lock().await.as_ref().unwrap().expires;
        assert!(handle.receive(1, &fragment(4, 0, &[7; 12]), expiry).await);
        assert!(handle.due(expiry).await.is_none());
        assert_eq!(handle.deadline().await, None);
        {
            let guard = handle.state.lock().await;
            let state = guard.as_ref().unwrap();
            assert!(state.packets.is_none());
            assert_eq!(state.expected, [0; 12]);
            assert_eq!(state.covered, 0);
            assert!(!state.pending);
        }
        assert!(!handle.receive(2, &fragment(4, 0, &[7; 12]), expiry).await);
        assert!(!handle.receive(1, &fragment(5, 0, &[7; 12]), expiry).await);
        handle.clear().await;
        assert!(!handle.receive(1, &fragment(4, 0, &[7; 12]), expiry).await);
    }

    #[tokio::test]
    async fn association_ownership_does_not_follow_an_equal_epoch_and_sequence() {
        let first = FinalFlightHandle::default();
        let second = FinalFlightHandle::default();
        first.install(1, 4, [7; 12], Vec::new()).await;
        second.install(1, 4, [9; 12], Vec::new()).await;
        let now = Instant::now();
        assert!(first.receive(1, &fragment(4, 0, &[7; 12]), now).await);
        // Even equal epoch/sequence metadata does not share accepted bytes.
        // This calls the private matcher directly; no peer record is altered.
        assert!(second.receive(1, &fragment(4, 0, &[7; 12]), now).await);
        assert!(!second.state.lock().await.as_ref().unwrap().pending);
        assert!(second.receive(1, &fragment(4, 0, &[9; 12]), now).await);
        first.clear().await;
        assert!(second.state.lock().await.as_ref().unwrap().pending);
        assert_eq!(first.deadline().await, None);
    }

    async fn blocked_writer_owner() -> (
        FinalFlightHandle,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<PacketSendRequest>,
        Arc<mpsc::Sender<PacketSendRequest>>,
    ) {
        let handle = FinalFlightHandle::default();
        handle.install(1, 4, [7; 12], Vec::new()).await;
        {
            let mut guard = handle.state.lock().await;
            let state = guard.as_mut().unwrap();
            state.pending = true;
            state.next_retry = Instant::now();
        }
        let (tx, rx) = mpsc::channel(1);
        let writer = Arc::new(tx);
        writer.send((Vec::new(), None)).await.unwrap();
        let task = handle.start(writer.clone());
        // Wait for the retained response clone to reach queue backpressure.
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.state.lock().await.as_ref().unwrap().pending {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        (handle, task, rx, writer)
    }

    #[tokio::test]
    async fn blocked_writer_cannot_extend_expiry_or_retain_task_arcs() {
        let (handle, task, mut rx, writer) = blocked_writer_owner().await;
        handle.state.lock().await.as_mut().unwrap().expires = Instant::now();
        handle.changed.notify_one();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(rx.try_recv().is_ok()); // Only the pre-existing sentinel.
        assert!(rx.try_recv().is_err());
        assert_eq!(Arc::strong_count(&writer), 1);
        assert_eq!(Arc::strong_count(&handle.state), 1);
        let state = handle.state.lock().await;
        let state = state.as_ref().unwrap();
        assert!(state.packets.is_none());
        assert_eq!(state.expected, [0; 12]);
    }

    #[tokio::test]
    async fn close_cancels_blocked_queue_handoff_without_a_late_response() {
        let (handle, task, mut rx, writer) = blocked_writer_owner().await;
        handle.clear().await;
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
        assert_eq!(Arc::strong_count(&writer), 1);
        assert_eq!(Arc::strong_count(&handle.state), 1);
        assert!(handle.state.lock().await.is_none());
    }
}
