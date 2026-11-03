//! Client-side FIDBF submission signer.

use std::{fs, path::PathBuf, process::ExitCode};

use clap::Parser;
use relic_crypto::{SystemSigner, read_secret_file};
use relic_ingest::{FidbfIngestManifest, sign_fidbf_manifest};

#[derive(Debug, Parser)]
#[command(about = "Verify and sign a RELIC FIDBF manifest on the analyst machine")]
struct Arguments {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    fidbf_object: PathBuf,
    #[arg(long)]
    analyst_key: PathBuf,
    #[arg(long)]
    analyst_key_passphrase_file: Option<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relic-sign-fidbf: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let manifest: FidbfIngestManifest = serde_json::from_slice(&fs::read(&arguments.manifest)?)?;
    let passphrase = arguments
        .analyst_key_passphrase_file
        .as_ref()
        .map(read_secret_file)
        .transpose()?;
    let signer = SystemSigner::from_openssh_file(
        &arguments.analyst_key,
        passphrase.as_ref().map(|value| value.as_slice()),
    )?;
    let submission = sign_fidbf_manifest(manifest, &arguments.fidbf_object, &signer)?;
    let mut output = serde_json::to_vec_pretty(&submission)?;
    output.push(b'\n');
    fs::write(&arguments.output, output)?;
    Ok(())
}
