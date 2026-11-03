//! One-shot FIDBF ingestion command.

use std::{fs, path::PathBuf, process::ExitCode};

use clap::Parser;
use relic_crypto::{SystemSigner, read_secret_file};
use relic_ingest::{SignedFidbfIngestManifest, connect, ingest_fidbf};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(about = "Verify, sign and atomically admit one RELIC FIDBF manifest")]
struct Arguments {
    #[arg(long, env = "RELIC_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    fidbf_object: PathBuf,
    #[arg(long, env = "RELIC_INTEGRITY_SYSTEM_USER_ID")]
    integrity_system_user_id: Uuid,
    #[arg(long, env = "RELIC_INTEGRITY_KEY")]
    integrity_key: PathBuf,
    #[arg(long, env = "RELIC_INTEGRITY_KEY_PASSPHRASE_FILE")]
    integrity_key_passphrase_file: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relic-ingest-fidbf: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let manifest_bytes = fs::read(&arguments.manifest)?;
    let manifest: SignedFidbfIngestManifest = serde_json::from_slice(&manifest_bytes)?;

    let integrity_passphrase =
        load_optional_secret(arguments.integrity_key_passphrase_file.as_ref())?;
    let integrity_signer = SystemSigner::from_openssh_file(
        &arguments.integrity_key,
        integrity_passphrase.as_ref().map(|value| value.as_slice()),
    )?;

    let mut client = connect(&arguments.database_url)?;
    let result = ingest_fidbf(
        &mut client,
        &manifest,
        &arguments.fidbf_object,
        arguments.integrity_system_user_id,
        &integrity_signer,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn load_optional_secret(
    path: Option<&PathBuf>,
) -> Result<Option<Zeroizing<Vec<u8>>>, relic_crypto::KeyLoadError> {
    path.map(read_secret_file).transpose()
}
