//! Deterministic integrity-chain calculation and signing.
//!
//! The database adapter must perform tip locking, authoritative-row inserts
//! and integrity-row insertion in one transaction. This crate deliberately
//! contains no database connection or private-key loading code.

use relic_crypto::{Digest32, SystemSigner, hash_fields, verify_digest_signature};

const CHAIN_HASH_DOMAIN: &[u8] = b"RELIC:integrity-chain-hash:v1";
const SIGNATURE_DOMAIN: &[u8] = b"RELIC:integrity-system-signature:v1";

/// Unsigned, canonical fields committed by an integrity-chain entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityEnvelope {
    /// Identifier of the source record being admitted.
    pub source_id: String,
    /// Fixed source-type discriminator.
    pub source_type: String,
    /// Hash of the admitted record's canonical bytes.
    pub record_hash: Digest32,
    /// Previous chain hash, or `None` for the one genesis entry.
    pub prev_hash: Option<Digest32>,
    /// Canonical format version.
    pub format_version: u32,
    /// Worker-selected UTC timestamp in Unix microseconds.
    pub created_at_unix_micros: i64,
    /// Database identity of the integrity-signing system account.
    pub system_uid: String,
}

impl IntegrityEnvelope {
    /// Calculate the chain hash over every field of this envelope.
    #[must_use]
    pub fn chain_hash(&self) -> Digest32 {
        let previous = self
            .prev_hash
            .map_or([0_u8; 32], |digest| *digest.as_bytes());
        let has_previous = [u8::from(self.prev_hash.is_some())];
        hash_fields(
            CHAIN_HASH_DOMAIN,
            &[
                self.source_id.as_bytes(),
                self.source_type.as_bytes(),
                self.record_hash.as_bytes(),
                &has_previous,
                &previous,
                &self.format_version.to_be_bytes(),
                &self.created_at_unix_micros.to_be_bytes(),
                self.system_uid.as_bytes(),
            ],
        )
    }
}

/// Complete integrity entry ready for atomic insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIntegrityEntry {
    /// Fields included in the chain hash.
    pub envelope: IntegrityEnvelope,
    /// Domain-separated chain hash.
    pub chain_hash: Digest32,
    /// Ed25519 signature made by the integrity system identity.
    pub system_signature: [u8; 64],
}

impl SignedIntegrityEntry {
    /// Strictly verify the chain hash and its signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical envelope hash differs from the stored
    /// chain hash, or if the system signature is invalid.
    pub fn verify(&self, verifying_key: &[u8; 32]) -> Result<(), VerificationError> {
        if self.envelope.chain_hash() != self.chain_hash {
            return Err(VerificationError::ChainHashMismatch);
        }
        verify_digest_signature(
            verifying_key,
            SIGNATURE_DOMAIN,
            &self.chain_hash,
            &self.system_signature,
        )
        .map_err(|_| VerificationError::InvalidSignature)
    }
}

/// Build and sign an integrity entry after the database tip has been locked.
#[must_use]
pub fn sign_entry(envelope: IntegrityEnvelope, signer: &SystemSigner) -> SignedIntegrityEntry {
    let chain_hash = envelope.chain_hash();
    let system_signature = signer.sign_digest(SIGNATURE_DOMAIN, &chain_hash);
    SignedIntegrityEntry {
        envelope,
        chain_hash,
        system_signature,
    }
}

/// Integrity verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// Stored chain hash differs from the canonical envelope hash.
    ChainHashMismatch,
    /// Signature is not valid for the chain hash and public key.
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use relic_crypto::sha256;

    use super::*;

    fn envelope() -> IntegrityEnvelope {
        IntegrityEnvelope {
            source_id: "01950f2a-test".into(),
            source_type: "BSIM".into(),
            record_hash: sha256(b"canonical record"),
            prev_hash: Some(sha256(b"previous")),
            format_version: 1,
            created_at_unix_micros: 1_800_000_000_123_456,
            system_uid: "integrity-worker".into(),
        }
    }

    #[test]
    fn entry_is_deterministic_and_verifiable() {
        let signer = SystemSigner::from_seed([11; 32]);
        let first = sign_entry(envelope(), &signer);
        let second = sign_entry(envelope(), &signer);
        assert_eq!(first, second);
        assert_eq!(first.verify(&signer.verifying_key()), Ok(()));
    }

    #[test]
    fn every_envelope_field_is_committed() {
        let baseline = envelope().chain_hash();
        let mut changed = envelope();
        changed.source_id.push('x');
        assert_ne!(baseline, changed.chain_hash());

        let mut changed = envelope();
        changed.created_at_unix_micros += 1;
        assert_ne!(baseline, changed.chain_hash());

        let mut changed = envelope();
        changed.prev_hash = None;
        assert_ne!(baseline, changed.chain_hash());
    }

    #[test]
    fn tampering_is_rejected() {
        let signer = SystemSigner::from_seed([11; 32]);
        let mut entry = sign_entry(envelope(), &signer);
        entry.envelope.source_type = "FIDBF".into();
        assert_eq!(
            entry.verify(&signer.verifying_key()),
            Err(VerificationError::ChainHashMismatch)
        );
    }
}
