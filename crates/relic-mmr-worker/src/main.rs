//! One-shot PostgreSQL MMR reconciliation and checkpoint command.

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use relic_crypto::{SystemSigner, read_secret_file};
use relic_mmr_worker::{checkpoint_postgres, connect};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(about = "Rebuild, verify and atomically checkpoint the RELIC integrity MMR")]
struct Arguments {
    #[arg(long, env = "RELIC_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, default_value_t = 1)]
    format_version: u32,
    #[arg(long, env = "RELIC_MMR_SYSTEM_USER_ID")]
    system_user_id: Uuid,
    #[arg(long, env = "RELIC_MMR_KEY")]
    key: PathBuf,
    #[arg(long, env = "RELIC_MMR_KEY_PASSPHRASE_FILE")]
    key_passphrase_file: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relic-checkpoint-mmr: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let passphrase = load_optional_secret(arguments.key_passphrase_file.as_ref())?;
    let signer = SystemSigner::from_openssh_file(
        &arguments.key,
        passphrase.as_ref().map(|value| value.as_slice()),
    )?;
    let mut client = connect(&arguments.database_url)?;
    let result = checkpoint_postgres(
        &mut client,
        arguments.format_version,
        arguments.system_user_id,
        &signer,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn load_optional_secret(
    path: Option<&PathBuf>,
) -> Result<Option<Zeroizing<Vec<u8>>>, relic_crypto::KeyLoadError> {
    path.map(read_secret_file).transpose()
}
