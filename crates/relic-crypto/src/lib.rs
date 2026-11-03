//! Shared, versioned cryptographic primitives for RELIC workers.
//!
//! Private key loading and storage are intentionally outside this crate. A
//! caller supplies a 32-byte Ed25519 seed obtained from its key custodian.

use std::{error::Error, fmt, str::FromStr};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

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
    let mut hasher = Sha256::new();
    update_framed(&mut hasher, domain);
    for field in fields {
        update_framed(&mut hasher, field);
    }
    Digest32(hasher.finalize().into())
}

fn update_framed(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("field length exceeds u64");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

/// Ed25519 signer used by one narrowly scoped RELIC system identity.
pub struct SystemSigner(SigningKey);

impl SystemSigner {
    /// Construct a signer from a secret seed supplied by external key custody.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
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
}
