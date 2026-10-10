//! Qualification-only process driver. Public identity metadata, no network service.
use coaptic::provisioning::{OperationId, ReceiptStore, TelemetryOperation};
use coaptic_durable_host::{Authority, Journal, Stage};
use std::io::Write;
use std::path::Path;

#[path = "../../tests/support/mod.rs"]
mod support;

fn checkpoint(stage: Stage) -> std::io::Result<()> {
    if std::env::var("COAPTIC_FIXTURE_STOP").ok().as_deref() == Some(&format!("{stage:?}")) {
        println!("checkpoint:{stage:?}");
        std::io::stdout().flush()?;
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(1));
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: receipt_fixture init|commit|inspect FILE (qualification only)".into());
    }
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    let path = Path::new(&args[2]);
    match args[1].as_str() {
        "init" => {
            Journal::create(path, authority, 2)?;
            println!("initialized");
        }
        "commit" => {
            let mut journal = Journal::open(path, authority)?;
            journal.set_checkpoint(checkpoint);
            // Stable pending ID and complete content survive each process retry.
            let operation = TelemetryOperation::new(
                OperationId::new([7; 16]),
                policy.resource,
                Some(42),
                b"complete telemetry fixture",
            )
            .unwrap();
            let receipt = journal
                .commit(&policy.anchor, &policy.principal, &operation)
                .map_err(|e| format!("commit refused: {e:?}"))?;
            operation
                .accept_receipt(&receipt.encode())
                .map_err(|e| format!("receipt refused: {e:?}"))?;
            println!(
                "effects:{} receipt:{}",
                journal.effects().unwrap(),
                receipt.sequence()
            );
        }
        "inspect" => {
            println!(
                "effects:{}",
                Journal::open(path, authority)?.effects().unwrap()
            );
        }
        _ => return Err("unknown qualification command".into()),
    }
    Ok(())
}
