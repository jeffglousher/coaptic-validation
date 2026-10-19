use coaptic::app::diagnostics::Reason;
use coaptic_durable_host::diagnostics::{Diagnostics, EncodeError, Error};

fn sample(at_ms: u64) -> coaptic::app::diagnostics::Snapshot {
    struct Io;
    impl coaptic::storage::DatagramTransport for Io {
        type Error = ();
    }
    impl coaptic::storage::DatagramIo for Io {
        fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, coaptic::Endpoint)>, ()> {
            Ok(None)
        }
        fn send(&mut self, _: coaptic::Endpoint, bytes: &[u8]) -> Result<usize, ()> {
            Ok(bytes.len())
        }
    }
    coaptic::App::with_resources(coaptic::resources::SmallDevice::new())
        .deterministic_for_tests()
        .allow_unprotected()
        .bind(Io)
        .unwrap()
        .diagnostic_snapshot(at_ms)
}

#[test]
fn bounded_cbor_golden_and_atomic_short_output() {
    let diagnostics = Diagnostics::new(42);
    let report = diagnostics.report().unwrap();
    let mut short = [0xa5; 1];
    assert!(matches!(
        report.encode(&mut short),
        Err(EncodeError::TooSmall { .. })
    ));
    assert_eq!(short, [0xa5; 1]);
    let mut output = [0; 256];
    let n = report.encode(&mut output).unwrap();
    assert_eq!(
        &output[..n],
        &[
            0x86, 0x01, 0x18, 0x2a, 0x8c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf6, 0xf6,
        ]
    );
    diagnostics.sample(42, sample(u64::MAX)).unwrap();
    let report = diagnostics.report().unwrap();
    let mut storage = [0; 2048];
    let n = report.encode(&mut storage).unwrap();
    let mut exact = vec![0; n];
    assert_eq!(report.encode(&mut exact), Ok(n));
    assert_eq!(exact, &storage[..n]);
    let mut short = vec![0xa5; n - 1];
    assert_eq!(
        report.encode(&mut short),
        Err(EncodeError::TooSmall {
            required: n,
            available: n - 1
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xa5));
}

#[test]
fn concurrent_record_sample_export_and_linearized_reset() {
    let diagnostics = std::sync::Arc::new(Diagnostics::new(7));
    let snapshot = sample(10);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let diagnostics = &diagnostics;
            scope.spawn(move || {
                for _ in 0..100 {
                    diagnostics.record(7, Reason::Capacity).unwrap();
                    diagnostics.sample(7, snapshot).unwrap();
                    let report = diagnostics.report().unwrap();
                    let mut output = [0; 2048];
                    report.encode(&mut output).unwrap();
                }
            });
        }
    });
    let before = diagnostics.report().unwrap();
    assert_eq!(before.recorder.count(Reason::Capacity), 400);
    assert_eq!(before.recorder.samples(), 400);
    diagnostics.reset().unwrap();
    // An old capture published after reset belongs to the new recording window.
    diagnostics.sample(7, snapshot).unwrap();
    assert_eq!(diagnostics.report().unwrap().recorder.samples(), 1);
    assert_eq!(
        diagnostics
            .report()
            .unwrap()
            .recorder
            .count(Reason::Capacity),
        0
    );
    assert_eq!(before.recorder.count(Reason::Capacity), 400);
    assert_eq!(diagnostics.sample(8, snapshot), Err(Error::WrongSource));
    assert_eq!(
        diagnostics.record(8, Reason::Security),
        Err(Error::WrongSource)
    );
    assert_eq!(diagnostics.sample(7, sample(9)), Err(Error::StaleSample));
    assert_eq!(diagnostics.report().unwrap().recorder.samples(), 1);
    // Reset and recording share one lock; competing operations remain usable.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..100 {
                diagnostics.reset().unwrap();
            }
        });
        scope.spawn(|| {
            for _ in 0..100 {
                diagnostics.record(7, Reason::Capacity).unwrap();
                diagnostics.sample(7, snapshot).unwrap();
                diagnostics
                    .report()
                    .unwrap()
                    .encode(&mut [0; 2048])
                    .unwrap();
            }
        });
    });
    diagnostics.reset().unwrap();
    diagnostics.record(7, Reason::Transport).unwrap();
    diagnostics.sample(7, snapshot).unwrap();
    let after = diagnostics.report().unwrap();
    assert_eq!(after.recorder.samples(), 1);
    assert_eq!(after.recorder.count(Reason::Transport), 1);
    assert_eq!(after.recorder.count(Reason::Capacity), 0);
    drop(diagnostics);
    assert_eq!(before.recorder.samples(), 400);
}

#[test]
fn writer_runs_without_lock_and_failure_preserves_report() {
    struct Writer<'a> {
        diagnostics: &'a Diagnostics,
    }
    impl std::io::Write for Writer<'_> {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.diagnostics.record(3, Reason::Transport).unwrap();
            Err(std::io::Error::other("injected failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let diagnostics = Diagnostics::new(3);
    let report = diagnostics.report().unwrap();
    assert!(
        report
            .write_to(
                &mut [0; 256],
                &mut Writer {
                    diagnostics: &diagnostics
                }
            )
            .is_err()
    );
    assert_eq!(
        diagnostics
            .report()
            .unwrap()
            .recorder
            .count(Reason::Transport),
        1
    );
    assert_eq!(report.recorder.count(Reason::Transport), 0);
}
