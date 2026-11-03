//! Shared, versioned cryptographic primitives for RELIC workers.
//!
//! Private keys are loaded only by the producing process. Analyst keys belong
//! on the analyst's machine; server-side ingestion verifies their signatures
//! with the public key registered in PostgreSQL. RELIC system workers load only
//! their own narrowly scoped service keys.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    str::FromStr,
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use ssh_key::PrivateKey;
use thiserror::Error as ThisError;
use zeroize::Zeroizing;

/// A SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Construct a digest from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Error returned when a hexadecimal digest is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseDigestError;

impl fmt::Display for ParseDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected exactly 64 lowercase or uppercase hexadecimal characters")
    }
}

impl Error for ParseDigestError {}

impl FromStr for Digest32 {
    type Err = ParseDigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(ParseDigestError);
        }

        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(ParseDigestError)?;
            let low = decode_hex(pair[1]).ok_or(ParseDigestError)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Hash bytes exactly as supplied.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Digest32 {
    Digest32(Sha256::digest(bytes).into())
}

/// Hash an unambiguous, domain-separated sequence of byte fields.
///
/// Every domain and field is prefixed with its big-endian `u64` length.
#[must_use]
pub fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> Digest32 {
    sha256(&encode_fields(domain, fields))
}

/// Encode an unambiguous, domain-separated sequence of byte fields.
///
/// The returned bytes are suitable for deterministic multi-algorithm hashing
/// when a compatibility digest must cover the same canonical value.
#[must_use]
pub fn encode_fields(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let capacity = 8 + domain.len() + fields.iter().map(|field| 8 + field.len()).sum::<usize>();
    let mut encoded = Vec::with_capacity(capacity);
    append_framed(&mut encoded, domain);
    for field in fields {
        append_framed(&mut encoded, field);
    }
    encoded
}

fn append_framed(encoded: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("field length exceeds u64");
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
}

/// Ed25519 signer used by one narrowly scoped RELIC system identity.
pub struct SystemSigner(SigningKey);

impl SystemSigner {
    /// Construct a signer from a secret seed supplied by external key custody.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Load an Ed25519 signer from an OpenSSH private-key file.
    ///
    /// The file must be a regular, non-symlink Unix file with no group or
    /// other permissions. Encrypted keys require a passphrase supplied by the
    /// caller. Secret bytes are zeroized after the signer is constructed.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe permissions, malformed or non-Ed25519 keys,
    /// missing/wrong passphrases, and filesystem failures.
    pub fn from_openssh_file(
        path: impl AsRef<Path>,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, KeyLoadError> {
        let path = path.as_ref();
        require_private_regular_file(path)?;
        let encoded = Zeroizing::new(fs::read(path).map_err(|source| KeyLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?);
        let parsed = PrivateKey::from_openssh(&*encoded).map_err(KeyLoadError::Decode)?;
        let decrypted = if parsed.is_encrypted() {
            let passphrase = passphrase.ok_or(KeyLoadError::PassphraseRequired)?;
            parsed.decrypt(passphrase).map_err(KeyLoadError::Decrypt)?
        } else {
            parsed
        };
        let keypair = decrypted
            .key_data()
            .ed25519()
            .ok_or(KeyLoadError::NotEd25519)?;
        let seed = Zeroizing::new(keypair.private.to_bytes());
        Ok(Self::from_seed(*seed))
    }

    /// Return the public verification key.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign a digest under an explicit message domain.
    #[must_use]
    pub fn sign_digest(&self, domain: &[u8], digest: &Digest32) -> [u8; 64] {
        let message = signing_message(domain, digest);
        self.0.sign(&message).to_bytes()
    }
}

/// Read a small secret file after enforcing private-file permissions.
///
/// One trailing LF or CRLF is removed so a passphrase can be created with a
/// normal line-oriented terminal command without making the newline secret.
///
/// # Errors
///
/// Returns an error when the path is unsafe, unreadable or empty.
pub fn read_secret_file(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>, KeyLoadError> {
    let path = path.as_ref();
    require_private_regular_file(path)?;
    let mut bytes = Zeroizing::new(fs::read(path).map_err(|source| KeyLoadError::Read {
        path: path.to_path_buf(),
        source,
    })?);
    if bytes.ends_with(b"\r\n") {
        let new_length = bytes.len() - 2;
        bytes.truncate(new_length);
    } else if bytes.ends_with(b"\n") {
        let new_length = bytes.len() - 1;
        bytes.truncate(new_length);
    }
    if bytes.is_empty() {
        return Err(KeyLoadError::EmptySecret(path.to_path_buf()));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn require_private_regular_file(path: &Path) -> Result<(), KeyLoadError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path).map_err(|source| KeyLoadError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(KeyLoadError::NotPrivateRegularFile(path.to_path_buf()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyLoadError::UnsafePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_regular_file(path: &Path) -> Result<(), KeyLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| KeyLoadError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeyLoadError::NotPrivateRegularFile(path.to_path_buf()));
    }
    Ok(())
}

/// Failure while loading private key material or an adjacent secret.
#[derive(Debug, ThisError)]
pub enum KeyLoadError {
    #[error("cannot inspect secret file {path}: {source}")]
    Metadata { path: PathBuf, source: io::Error },
    #[error("secret path is not a regular non-symlink file: {0}")]
    NotPrivateRegularFile(PathBuf),
    #[error("secret file {path} has unsafe mode {mode:04o}; remove group/other permissions")]
    UnsafePermissions { path: PathBuf, mode: u32 },
    #[error("cannot read secret file {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("secret file is empty: {0}")]
    EmptySecret(PathBuf),
    #[error("private key is encrypted but no passphrase was supplied")]
    PassphraseRequired,
    #[error("OpenSSH private key is malformed: {0}")]
    Decode(ssh_key::Error),
    #[error("OpenSSH private key could not be decrypted: {0}")]
    Decrypt(ssh_key::Error),
    #[error("private key is not Ed25519")]
    NotEd25519,
}

/// Strictly verify a domain-separated digest signature.
///
/// # Errors
///
/// Returns an error when the public key is malformed or the signature does not
/// strictly verify for the supplied domain and digest.
pub fn verify_digest_signature(
    verifying_key: &[u8; 32],
    domain: &[u8],
    digest: &Digest32,
    signature: &[u8; 64],
) -> Result<(), ed25519_dalek::SignatureError> {
    let key = VerifyingKey::from_bytes(verifying_key)?;
    let signature = Signature::from_bytes(signature);
    key.verify_strict(&signing_message(domain, digest), &signature)
}

fn signing_message(domain: &[u8], digest: &Digest32) -> Vec<u8> {
    let domain_length = u64::try_from(domain.len()).expect("domain length exceeds u64");
    let mut message = Vec::with_capacity(8 + domain.len() + 32);
    message.extend_from_slice(&domain_length.to_be_bytes());
    message.extend_from_slice(domain);
    message.extend_from_slice(digest.as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use rand_core::OsRng;
    use ssh_key::{
        LineEnding,
        private::{Ed25519Keypair, KeypairData},
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn digest_hex_round_trips() {
        let digest = sha256(b"RELIC");
        assert_eq!(digest.to_string().parse(), Ok(digest));
    }

    #[test]
    fn framing_prevents_field_ambiguity() {
        assert_ne!(
            hash_fields(b"test", &[b"ab", b"c"]),
            hash_fields(b"test", &[b"a", b"bc"])
        );
    }

    #[test]
    fn canonical_encoding_matches_hash_fields() {
        let encoded = encode_fields(b"domain", &[b"ab", b"c"]);
        assert_eq!(sha256(&encoded), hash_fields(b"domain", &[b"ab", b"c"]));
    }

    #[test]
    fn signatures_are_domain_separated_and_strictly_verified() {
        let signer = SystemSigner::from_seed([7; 32]);
        let digest = sha256(b"checkpoint");
        let signature = signer.sign_digest(b"RELIC:test:v1", &digest);

        assert!(
            verify_digest_signature(
                &signer.verifying_key(),
                b"RELIC:test:v1",
                &digest,
                &signature
            )
            .is_ok()
        );
        assert!(
            verify_digest_signature(
                &signer.verifying_key(),
                b"RELIC:other:v1",
                &digest,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn encrypted_openssh_ed25519_key_loads_and_wrong_passphrase_fails() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("identity");
        let keypair = Ed25519Keypair::from_seed(&[19; 32]);
        let private_key = PrivateKey::new(KeypairData::Ed25519(keypair), "test").unwrap();
        let encrypted = private_key.encrypt(&mut OsRng, b"correct horse").unwrap();
        encrypted.write_openssh_file(&path, LineEnding::LF).unwrap();

        let signer = SystemSigner::from_openssh_file(&path, Some(b"correct horse")).unwrap();
        assert_eq!(
            signer.verifying_key().as_slice(),
            private_key.key_data().ed25519().unwrap().public.as_ref()
        );
        assert!(SystemSigner::from_openssh_file(&path, Some(b"wrong")).is_err());
    }

    #[test]
    fn group_readable_private_key_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("identity");
        fs::write(&path, b"not even parsed").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            SystemSigner::from_openssh_file(&path, None),
            Err(KeyLoadError::UnsafePermissions { .. })
        ));
    }
}
