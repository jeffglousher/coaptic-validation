//! Offline record-policy tests: no sockets or handshake-message mutation.
use super::*;
use crate::cipher_suite::cipher_suite_aes_128_ccm::CipherSuiteAes128Ccm;
use crate::client_certificate_type::ClientCertificateType;
use crate::crypto::crypto_ccm::CryptoCcmTagLen;

fn suite(secret: u8, client: bool, psk: bool) -> CipherSuiteAes128Ccm {
    let mut cipher = CipherSuiteAes128Ccm::new(
        ClientCertificateType::Unsupported,
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        psk,
        CryptoCcmTagLen::CryptoCcm8TagLength,
    );
    cipher
        .init(&[secret; 48], &[1; 32], &[2; 32], client)
        .unwrap();
    cipher
}
fn wire(secret: u8) -> Vec<u8> {
    let header = RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 1,
        sequence_number: 0,
        content_len: 4,
    };
    let mut plain = Vec::new();
    header.marshal(&mut plain).unwrap();
    plain.extend_from_slice(b"test");
    suite(secret, true, true).encrypt(&header, &plain).unwrap()
}
fn reader(
    psk: bool,
) -> (
    ConnReaderContext,
    mpsc::Receiver<Result<Vec<u8>>>,
    mpsc::Receiver<PacketSendRequest>,
) {
    let (decrypted_tx, decrypted_rx) = mpsc::channel(2);
    let (packet_tx, packet_rx) = mpsc::channel(2);
    let (handshake_tx, _) = mpsc::channel(1);
    let (_, handshake_done_rx) = mpsc::channel(1);
    (
        ConnReaderContext {
            final_flight: FinalFlightHandle::default(),
            is_client: false,
            replay_protection_window: 64,
            replay_detector: vec![],
            decrypted_tx,
            encrypted_packets: vec![],
            fragment_buffer: FragmentBuffer::new(),
            cache: HandshakeCache::new(),
            cipher_suite: Arc::new(Mutex::new(Some(Box::new(suite(3, false, psk))))),
            remote_epoch: Arc::new(AtomicU16::new(1)),
            handshake_tx,
            handshake_done_rx,
            packet_tx: Arc::new(packet_tx),
        },
        decrypted_rx,
        packet_rx,
    )
}
fn assert_alert(packets: Vec<Packet>) {
    assert_eq!(packets.len(), 1);
    assert!(!packets[0].reset_local_sequence_number);
    assert!(!packets[0].should_encrypt);
    let Content::Alert(alert) = &packets[0].record.content else {
        panic!("expected alert")
    };
    assert_eq!(alert.alert_level, AlertLevel::Fatal);
    assert_eq!(alert.alert_description, AlertDescription::BadRecordMac);
}
#[tokio::test]
async fn record_policy_immediate_and_queued_auth_failure_close_without_delivery() {
    for queued in [false, true] {
        let (mut ctx, mut application, mut packets) = reader(true);
        let epoch = Arc::new(AtomicU16::new(0));
        let complete = Arc::new(AtomicBool::new(false));
        let result = if queued {
            ctx.remote_epoch.store(0, Ordering::SeqCst);
            let (hs, alert, error) =
                DTLSConn::handle_incoming_packet(&mut ctx, wire(9), true).await;
            assert!(!hs && alert.is_none() && error.is_none());
            assert_eq!(ctx.encrypted_packets.len(), 1);
            ctx.remote_epoch.store(1, Ordering::SeqCst);
            let pending = std::mem::take(&mut ctx.encrypted_packets);
            DTLSConn::handle_queued_packets(&mut ctx, &epoch, &complete, pending).await
        } else {
            let (input, output) = util::conn::conn_pipe::pipe();
            let input: Arc<dyn Conn + Send + Sync> = Arc::new(input);
            output.send(&wire(9)).await.unwrap();
            let (_, mut queue) = mpsc::channel(1);
            DTLSConn::read_and_buffer(
                &mut ctx,
                &input,
                &mut queue,
                &mut [0; 128],
                &epoch,
                &complete,
            )
            .await
        };
        assert_eq!(result.unwrap_err(), Error::ErrAlertFatalOrClose);
        assert!(application.try_recv().is_err());
        assert_alert(packets.try_recv().unwrap().0);
        assert!(packets.try_recv().is_err());
    }
}
#[tokio::test]
async fn record_policy_structural_refusal_keeps_replay_and_valid_record_usable() {
    let (mut ctx, mut application, mut packets) = reader(true);
    let mut short = wire(3);
    short.truncate(RECORD_LAYER_HEADER_SIZE + 9);
    short[11..13].copy_from_slice(&9u16.to_be_bytes());
    let (hs, alert, error) = DTLSConn::handle_incoming_packet(&mut ctx, short, true).await;
    assert!(!hs && alert.is_none() && error.is_none());
    assert!(application.try_recv().is_err());
    assert!(packets.try_recv().is_err());
    let (hs, alert, error) = DTLSConn::handle_incoming_packet(&mut ctx, wire(3), true).await;
    assert!(!hs && alert.is_none() && error.is_none());
    assert_eq!(application.try_recv().unwrap().unwrap(), b"test");
    let (hs, alert, error) = DTLSConn::handle_incoming_packet(&mut ctx, wire(3), true).await;
    assert!(!hs && alert.is_none() && error.is_none());
    assert!(application.try_recv().is_err());
}
#[tokio::test]
async fn record_policy_non_psk_authentication_retains_silent_discard() {
    let (mut ctx, mut application, mut packets) = reader(false);
    let (hs, alert, error) = DTLSConn::handle_incoming_packet(&mut ctx, wire(9), true).await;
    assert!(!hs && alert.is_none() && error.is_none());
    assert!(application.try_recv().is_err());
    assert!(packets.try_recv().is_err());
}

#[test]
fn record_policy_other_psk_and_non_psk_classification_is_preserved() {
    let error = Error::Other("test-only cipher failure".into());
    assert!(record_decrypt_alert(
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
        false,
        &Error::ErrInvalidMac
    )
    .is_none());
    for id in [
        CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
    ] {
        assert!(record_decrypt_alert(id, true, &error).is_none());
        assert!(record_decrypt_alert(id, true, &Error::ErrInvalidPacketLength).is_none());
        assert_eq!(
            record_decrypt_alert(id, true, &Error::ErrInvalidMac)
                .unwrap()
                .alert_description,
            AlertDescription::BadRecordMac
        );
    }
}
