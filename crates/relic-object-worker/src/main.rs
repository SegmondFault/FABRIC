//! Object-worker service entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("relic-object-worker has no configured object-source adapter; refusing to start");
    ExitCode::FAILURE
}
