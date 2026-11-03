//! Foundational FABRIC domain types.
//!
//! FIDBF files are opaque server-side objects. Analysts submit their metadata
//! and function columns; this crate validates the values before persistence.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

macro_rules! lowercase_hex_type {
    ($name:ident, $length:expr, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Construct and validate a lowercase hexadecimal value.
            ///
            /// # Errors
            ///
            /// Returns an error if the value is not exactly the required
            /// number of lowercase hexadecimal characters.
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                validate_lowercase_hex(&value, $length, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

lowercase_hex_type!(Sha256Hex, 64, "sha256");
lowercase_hex_type!(Md5Hex, 32, "md5");
lowercase_hex_type!(FidHash, 16, "FID hash");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FidbfColumns {
    pub binary_id: Uuid,
    pub storage_path: String,
    pub sha256: Sha256Hex,
    pub md5: Md5Hex,
    pub submitted_by_user_id: Uuid,
    pub signature: Vec<u8>,
    pub source_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FunctionColumns {
    pub name: Option<String>,
    pub binary_id: Uuid,
    pub full_hash: FidHash,
    pub specific_hash: FidHash,
    pub file_offset: Option<u64>,
    pub virtual_address: Option<u64>,
    pub size_bytes: Option<u64>,
    pub section_name: Option<String>,
    pub symbol_name: Option<String>,
    pub mangled_name: Option<String>,
    pub demangled_name: Option<String>,
    pub is_import: bool,
    pub is_export: bool,
    pub is_thunk: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FidbfSubmission {
    pub fidbf: FidbfColumns,
    pub functions: Vec<FunctionColumns>,
}

impl FidbfSubmission {
    /// Validate relationships and non-empty values spanning the submission.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty object path or signature, or when a
    /// function refers to a different binary than the FIDBF submission.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.fidbf.storage_path.trim().is_empty() {
            return Err(ValidationError::EmptyField("storage_path"));
        }
        if self.fidbf.signature.is_empty() {
            return Err(ValidationError::EmptyField("signature"));
        }
        if self
            .functions
            .iter()
            .any(|function| function.binary_id != self.fidbf.binary_id)
        {
            return Err(ValidationError::BinaryMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("{field} must be exactly {length} lowercase hexadecimal characters")]
    InvalidHex { field: &'static str, length: usize },

    #[error("{0} must not be empty")]
    EmptyField(&'static str),

    #[error("every function binary_id must match the FIDBF binary_id")]
    BinaryMismatch,
}

fn validate_lowercase_hex(
    value: &str,
    length: usize,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(ValidationError::InvalidHex { field, length })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission() -> FidbfSubmission {
        let binary_id = Uuid::new_v4();
        FidbfSubmission {
            fidbf: FidbfColumns {
                binary_id,
                storage_path: "objects/fidbf/example.fidbf".into(),
                sha256: Sha256Hex::new("a".repeat(64)).unwrap(),
                md5: Md5Hex::new("b".repeat(32)).unwrap(),
                submitted_by_user_id: Uuid::new_v4(),
                signature: vec![1, 2, 3],
                source_id: Uuid::new_v4(),
            },
            functions: vec![FunctionColumns {
                name: Some("example".into()),
                binary_id,
                full_hash: FidHash::new("0123456789abcdef").unwrap(),
                specific_hash: FidHash::new("fedcba9876543210").unwrap(),
                file_offset: Some(64),
                virtual_address: Some(4096),
                size_bytes: Some(32),
                section_name: Some(".text".into()),
                symbol_name: None,
                mangled_name: None,
                demangled_name: None,
                is_import: false,
                is_export: false,
                is_thunk: false,
            }],
        }
    }

    #[test]
    fn valid_submission_is_accepted() {
        assert_eq!(submission().validate(), Ok(()));
    }

    #[test]
    fn malformed_hash_is_rejected_during_deserialization() {
        let error = serde_json::from_str::<FidHash>(r#""NOT-A-FID-HASH""#).unwrap_err();
        assert!(error.to_string().contains("lowercase hexadecimal"));
    }

    #[test]
    fn cross_binary_function_is_rejected() {
        let mut value = submission();
        value.functions[0].binary_id = Uuid::new_v4();
        assert_eq!(value.validate(), Err(ValidationError::BinaryMismatch));
    }

    #[test]
    fn empty_signature_is_rejected() {
        let mut value = submission();
        value.fidbf.signature.clear();
        assert_eq!(
            value.validate(),
            Err(ValidationError::EmptyField("signature"))
        );
    }
}
