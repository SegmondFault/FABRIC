//! Integrity-worker service entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("relic-integrity-worker has no configured database/key adapter; refusing to start");
    ExitCode::FAILURE
}
