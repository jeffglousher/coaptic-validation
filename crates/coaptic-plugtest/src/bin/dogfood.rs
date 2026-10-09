//! Timed coaptic ↔ coap-rs dogfood + coaptic↔coaptic Observe notify collect.
//! Mixed-stack Metrics must stay warm. `--oscore` adds a protected
//! GET/PUT/POST + Observe notify + Block1/Block2 loop (coaptic-only;
//! coap-rs has no OSCORE).
//!
//! ```text
//! cargo run -p coaptic-plugtest --bin dogfood
//! cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2
//! cargo run -p coaptic-plugtest --bin dogfood -- --json dogfood.json
//! cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood.json
//! cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore
//! cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood-oscore.json
//! ```

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use coaptic_plugtest::dogfood::{self, Config};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", Config::USAGE);
        return ExitCode::SUCCESS;
    }
    let cfg = match Config::from_args(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            let _ = writeln!(io::stderr(), "{e}");
            return ExitCode::from(2);
        }
    };
    match dogfood::run(cfg, io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(io::stderr(), "dogfood: {e}");
            ExitCode::from(1)
        }
    }
}
