//! Test-only handshake oracle, called with each executable's actual config.
use std::{sync::Arc, time::Duration};
use tokio::net::UdpSocket;
use webrtc_dtls::{cipher_suite::CipherSuiteId, config::Config, conn::DTLSConn};
use webrtc_util::conn::{Conn, Listener};

pub async fn check(dual: Config) {
    let ciphers = [
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
    ];
    assert_eq!(dual.cipher_suites, ciphers);
    for cipher in ciphers {
        // A single-suite counterpart forces actual authentication with that
        // cipher; inspecting an offer alone cannot prove compatibility.
        for dual_is_client in [true, false] {
            let mut single = dual.clone();
            single.cipher_suites = vec![cipher];
            let (client_config, server_config) = if dual_is_client {
                (dual.clone(), single)
            } else {
                (single, dual.clone())
            };
            let listener = webrtc_dtls::listener::listen("127.0.0.1:0", server_config)
                .await
                .unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .connect(listener.addr().await.unwrap())
                .await
                .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(
                    DTLSConn::new(Arc::new(socket), client_config, true, None),
                    listener.accept()
                )
            })
            .await;
            if result.is_err() {
                listener.close().await.unwrap();
            }
            let (client, server) = result.expect("bounded PSK handshake");
            if client.is_err() || server.is_err() {
                listener.close().await.unwrap();
            }
            let client = client.unwrap();
            let (server, _) = server.unwrap();
            let exchange = tokio::time::timeout(Duration::from_secs(1), async {
                let mut buffer = [0; 32];
                client.send(b"authenticated request").await.unwrap();
                let n = server.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], b"authenticated request");
                server.send(b"authenticated response").await.unwrap();
                let n = client.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], b"authenticated response");
            })
            .await;
            let cleanup = tokio::time::timeout(Duration::from_secs(1), async {
                let closed = tokio::join!(client.close(), server.close());
                listener.close().await.unwrap();
                closed
            })
            .await;
            exchange.expect("bounded authenticated application data");
            let (client_close, server_close) = cleanup.expect("bounded PSK shutdown");
            client_close.unwrap();
            server_close.unwrap();
        }
    }
}
