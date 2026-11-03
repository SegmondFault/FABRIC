//! MMR-worker service entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("relic-mmr-worker has no configured database/key adapter; refusing to start");
    ExitCode::FAILURE
}
