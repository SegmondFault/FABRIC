//! Streaming content-digest calculation and verification for admitted objects.
//!
//! SHA-256 is the security digest. MD5 is calculated only for interoperability
//! with existing corpora and tools; it must never be used as integrity proof.

use std::{
    fmt,
    io::{self, Read},
};

use md5::Md5;
use relic_crypto::Digest32;
use sha2::{Digest as _, Sha256};

/// Compatibility-only MD5 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompatibilityMd5([u8; 16]);

impl CompatibilityMd5 {
    /// Construct a compatibility digest from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the raw compatibility digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for CompatibilityMd5 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Both digests calculated from one exact byte stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectDigests {
    /// Security digest used by RELIC integrity operations.
    pub sha256: Digest32,
    /// Compatibility-only digest retained for ecosystem matching.
    pub md5: CompatibilityMd5,
}

/// Hash a reader once without retaining the complete object in memory.
///
/// # Errors
///
/// Returns the reader's I/O error if the complete object cannot be consumed.
pub fn digest_reader(mut reader: impl Read) -> io::Result<ObjectDigests> {
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
        md5.update(&buffer[..read]);
    }
    Ok(ObjectDigests {
        sha256: Digest32::from_bytes(sha256.finalize().into()),
        md5: CompatibilityMd5::from_bytes(md5.finalize().into()),
    })
}

/// Calculate both digests and reject either false claim.
///
/// # Errors
///
/// Returns an I/O error when the object cannot be read, or a mismatch error
/// when either calculated digest differs from its claimed value.
pub fn verify_reader(
    reader: impl Read,
    expected_sha256: Digest32,
    expected_md5: CompatibilityMd5,
) -> Result<ObjectDigests, VerifyError> {
    let actual = digest_reader(reader).map_err(VerifyError::Read)?;
    if actual.sha256 != expected_sha256 {
        return Err(VerifyError::Sha256Mismatch {
            expected: expected_sha256,
            actual: actual.sha256,
        });
    }
    if actual.md5 != expected_md5 {
        return Err(VerifyError::Md5Mismatch {
            expected: expected_md5,
            actual: actual.md5,
        });
    }
    Ok(actual)
}

/// Object verification failed before database admission.
#[derive(Debug)]
pub enum VerifyError {
    /// The object could not be read completely.
    Read(io::Error),
    /// The claimed SHA-256 digest did not match the exact bytes supplied.
    Sha256Mismatch {
        /// Claimed digest.
        expected: Digest32,
        /// Calculated digest.
        actual: Digest32,
    },
    /// The compatibility MD5 digest did not match the exact bytes supplied.
    Md5Mismatch {
        /// Claimed compatibility digest.
        expected: CompatibilityMd5,
        /// Calculated compatibility digest.
        actual: CompatibilityMd5,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "failed to read object: {error}"),
            Self::Sha256Mismatch { expected, actual } => write!(
                formatter,
                "SHA-256 mismatch: expected {expected}, calculated {actual}"
            ),
            Self::Md5Mismatch { expected, actual } => write!(
                formatter,
                "compatibility MD5 mismatch: expected {expected}, calculated {actual}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Sha256Mismatch { .. } | Self::Md5Mismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use relic_crypto::sha256;

    use super::*;

    #[test]
    fn streams_both_digests_and_accepts_exact_bytes() {
        let bytes = vec![0x5a; 150_000];
        let expected = digest_reader(Cursor::new(&bytes)).unwrap();
        assert_eq!(
            verify_reader(Cursor::new(bytes), expected.sha256, expected.md5).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_a_false_sha256_claim() {
        let actual = digest_reader(Cursor::new(b"object")).unwrap();
        let error =
            verify_reader(Cursor::new(b"object"), sha256(b"other"), actual.md5).unwrap_err();
        assert!(matches!(error, VerifyError::Sha256Mismatch { .. }));
    }

    #[test]
    fn rejects_a_false_compatibility_md5_claim() {
        let actual = digest_reader(Cursor::new(b"object")).unwrap();
        let error = verify_reader(
            Cursor::new(b"object"),
            actual.sha256,
            CompatibilityMd5::from_bytes([0; 16]),
        )
        .unwrap_err();
        assert!(matches!(error, VerifyError::Md5Mismatch { .. }));
    }
}
