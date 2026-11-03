//! Signed, atomic FIDBF admission for RELIC.
//!
//! This adapter verifies the supplied FIDBF, derives canonical digests and
//! signatures, then admits the source, batch, binary, FIDBF, functions and
//! integrity-chain row in one PostgreSQL transaction.

use std::{fmt, fs::File, path::Path, path::PathBuf, str::FromStr};

use chrono::{DateTime, Utc};
use md5::{Digest as _, Md5};
use postgres::{Client, IsolationLevel, NoTls, Transaction};
use relic_crypto::{Digest32, SystemSigner, encode_fields, sha256, verify_digest_signature};
use relic_domain::{FidHash, Md5Hex, Sha256Hex};
use relic_integrity_worker::{IntegrityEnvelope, sign_entry};
use relic_object_worker::{CompatibilityMd5, VerifyError, verify_reader};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use uuid::Uuid;

const SOURCE_SIGNATURE_DOMAIN: &[u8] = b"RELIC:analyst-source-signature:v1";
const BATCH_SIGNATURE_DOMAIN: &[u8] = b"RELIC:analyst-batch-signature:v1";
const FIDBF_SIGNATURE_DOMAIN: &[u8] = b"RELIC:analyst-fidbf-signature:v1";
const SOURCE_RECORD_DOMAIN: &[u8] = b"RELIC:source-record:v1";
const BINARY_RECORD_DOMAIN: &[u8] = b"RELIC:binary-record:v1";
const FUNCTION_RECORD_DOMAIN: &[u8] = b"RELIC:function-record:v1";
const BATCH_MANIFEST_DOMAIN: &[u8] = b"RELIC:batch-manifest:v1";
const FIDBF_RECORD_DOMAIN: &[u8] = b"RELIC:fidbf-record:v1";
const ADMISSION_RECORD_DOMAIN: &[u8] = b"RELIC:fidbf-admission:v1";

/// Complete analyst-supplied input for one FIDBF admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FidbfIngestManifest {
    pub analyst_user_id: Uuid,
    pub source: SourceInput,
    pub batch: BatchInput,
    pub binary: BinaryInput,
    pub fidbf: FidbfInput,
    pub functions: Vec<FunctionInput>,
}

/// Analyst-signed submission. The private key never accompanies this value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedFidbfIngestManifest {
    #[serde(flatten)]
    pub manifest: FidbfIngestManifest,
    pub analyst_signatures: AnalystSignatures,
}

/// Signatures made on the analyst's machine over canonical submission parts.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnalystSignatures {
    pub source: SignatureHex,
    pub batch: SignatureHex,
    pub fidbf: SignatureHex,
}

/// A 64-byte Ed25519 signature encoded as 128 hexadecimal characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureHex([u8; 64]);

impl SignatureHex {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Display for SignatureHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for SignatureHex {
    type Err = SignatureParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 128 {
            return Err(SignatureParseError);
        }
        let mut bytes = [0_u8; 64];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| SignatureParseError)?;
            bytes[index] = u8::from_str_radix(pair, 16).map_err(|_| SignatureParseError)?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for SignatureHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SignatureHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Error)]
#[error("expected exactly 128 hexadecimal characters")]
pub struct SignatureParseError;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceInput {
    pub source_id: Uuid,
    pub name: String,
    pub source_type: String,
    pub reference: Option<String>,
    pub snapshot_version: Option<String>,
    pub retrieved_at: DateTime<Utc>,
    pub is_ecological: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchInput {
    pub batch_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BinaryInput {
    pub binary_id: Uuid,
    pub content_sha256: Sha256Hex,
    pub content_md5: Md5Hex,
    pub size_bytes: i64,
    pub original_filename: Option<String>,
    pub format: Option<String>,
    pub architecture: Option<String>,
    pub bit_width: Option<i16>,
    pub endianness: Option<String>,
    pub platform: Option<String>,
    pub abi: Option<String>,
    pub object_type: Option<String>,
    /// Decimal unsigned integer text, allowing the schema's full NUMERIC(20,0).
    pub entry_point: Option<String>,
    pub image_base: Option<String>,
    pub build_id: Option<String>,
    pub is_stripped: Option<bool>,
    pub compiler: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FidbfInput {
    pub fidbf_id: Uuid,
    /// Immutable object-store path persisted in the catalogue.
    pub storage_path: String,
    pub sha256: Sha256Hex,
    pub md5: Md5Hex,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FunctionInput {
    pub function_id: Uuid,
    pub name: Option<String>,
    pub full_hash: FidHash,
    pub specific_hash: FidHash,
    pub file_offset: Option<i64>,
    pub virtual_address: Option<String>,
    pub size_bytes: Option<i64>,
    pub section_name: Option<String>,
    pub symbol_name: Option<String>,
    pub mangled_name: Option<String>,
    pub demangled_name: Option<String>,
    #[serde(default)]
    pub is_import: bool,
    #[serde(default)]
    pub is_export: bool,
    #[serde(default)]
    pub is_thunk: bool,
}

/// Database identities and digests returned after a committed admission.
#[derive(Clone, Debug, Serialize)]
pub struct IngestResult {
    pub source_id: Uuid,
    pub batch_id: Uuid,
    pub binary_id: Uuid,
    pub fidbf_id: Uuid,
    pub function_count: usize,
    pub integrity_id: i64,
    pub batch_sha256: String,
    pub batch_md5: String,
    pub chain_hash: String,
}

struct PreparedSubmission {
    source_bytes: Vec<u8>,
    batch_bytes: Vec<u8>,
    fidbf_bytes: Vec<u8>,
    batch_sha256: Digest32,
    batch_md5: CompatibilityMd5,
}

/// Verify the object and sign a submission on the analyst's machine.
///
/// # Errors
///
/// Returns an error for malformed input or an object digest mismatch.
pub fn sign_fidbf_manifest(
    manifest: FidbfIngestManifest,
    object_path: &Path,
    analyst_signer: &SystemSigner,
) -> Result<SignedFidbfIngestManifest, IngestError> {
    validate_manifest(&manifest)?;
    let prepared = prepare_submission(&manifest, object_path)?;
    Ok(SignedFidbfIngestManifest {
        analyst_signatures: AnalystSignatures {
            source: SignatureHex::from_bytes(
                analyst_signer
                    .sign_digest(SOURCE_SIGNATURE_DOMAIN, &sha256(&prepared.source_bytes)),
            ),
            batch: SignatureHex::from_bytes(
                analyst_signer.sign_digest(BATCH_SIGNATURE_DOMAIN, &prepared.batch_sha256),
            ),
            fidbf: SignatureHex::from_bytes(
                analyst_signer.sign_digest(FIDBF_SIGNATURE_DOMAIN, &sha256(&prepared.fidbf_bytes)),
            ),
        },
        manifest,
    })
}

/// Connect to PostgreSQL using its standard connection string.
///
/// # Errors
///
/// Returns PostgreSQL connection or TLS-negotiation errors.
pub fn connect(database_url: &str) -> Result<Client, IngestError> {
    Client::connect(database_url, NoTls).map_err(IngestError::Database)
}

/// Verify, sign and atomically admit one FIDBF manifest.
///
/// # Errors
///
/// Returns an error before commit for malformed input, object digest mismatch,
/// identity/key mismatch, revoked actors, chain conflicts or database errors.
pub fn ingest_fidbf(
    client: &mut Client,
    signed_manifest: &SignedFidbfIngestManifest,
    object_path: &Path,
    integrity_system_user_id: Uuid,
    integrity_signer: &SystemSigner,
) -> Result<IngestResult, IngestError> {
    let manifest = &signed_manifest.manifest;
    validate_manifest(manifest)?;
    let prepared = prepare_submission(manifest, object_path)?;
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .map_err(IngestError::Database)?;

    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('RELIC:integrity-sequencer:v1', 0))",
            &[],
        )
        .map_err(IngestError::Database)?;
    let analyst_public_key = verify_database_identity(
        &mut transaction,
        manifest.analyst_user_id,
        "human",
        Some("analyst"),
        None,
    )?;
    verify_analyst_signatures(
        &analyst_public_key,
        &prepared,
        &signed_manifest.analyst_signatures,
    )?;
    verify_database_identity(
        &mut transaction,
        integrity_system_user_id,
        "system",
        None,
        Some(&integrity_signer.verifying_key()),
    )?;

    let accepted_at_micros = database_clock_micros(&mut transaction)?;
    let accepted_at = DateTime::<Utc>::from_timestamp_micros(accepted_at_micros)
        .ok_or(IngestError::TimestampOutOfRange(accepted_at_micros))?;
    insert_authoritative_rows(
        &mut transaction,
        manifest,
        &prepared,
        &signed_manifest.analyst_signatures,
        accepted_at,
    )?;

    let (integrity_id, chain_hash) = insert_integrity_entry(
        &mut transaction,
        manifest,
        &prepared,
        accepted_at,
        accepted_at_micros,
        integrity_system_user_id,
        integrity_signer,
    )?;
    transaction.commit().map_err(IngestError::Database)?;

    Ok(IngestResult {
        source_id: manifest.source.source_id,
        batch_id: manifest.batch.batch_id,
        binary_id: manifest.binary.binary_id,
        fidbf_id: manifest.fidbf.fidbf_id,
        function_count: manifest.functions.len(),
        integrity_id,
        batch_sha256: prepared.batch_sha256.to_string(),
        batch_md5: prepared.batch_md5.to_string(),
        chain_hash,
    })
}

fn database_clock_micros(transaction: &mut Transaction<'_>) -> Result<i64, IngestError> {
    transaction
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
            &[],
        )
        .map_err(IngestError::Database)
        .map(|row| row.get(0))
}

fn insert_integrity_entry(
    transaction: &mut Transaction<'_>,
    manifest: &FidbfIngestManifest,
    prepared: &PreparedSubmission,
    accepted_at: DateTime<Utc>,
    accepted_at_micros: i64,
    system_user_id: Uuid,
    system_signer: &SystemSigner,
) -> Result<(i64, String), IngestError> {
    let previous_hash = transaction
        .query_opt(
            "SELECT chain_hash::text FROM catalogue.integrity ORDER BY integrity_id DESC LIMIT 1",
            &[],
        )
        .map_err(IngestError::Database)?
        .map(|row| row.get::<_, String>(0).parse::<Digest32>())
        .transpose()
        .map_err(|_| IngestError::MalformedChainTip)?;
    let accepted_at_bytes = accepted_at_micros.to_be_bytes();
    let record_bytes = encode_fields(
        ADMISSION_RECORD_DOMAIN,
        &[
            &prepared.source_bytes,
            &prepared.batch_bytes,
            &prepared.fidbf_bytes,
            &accepted_at_bytes,
            manifest.analyst_user_id.as_bytes(),
        ],
    );
    let signed_integrity = sign_entry(
        IntegrityEnvelope {
            source_id: manifest.source.source_id.to_string(),
            source_type: manifest.source.source_type.clone(),
            record_hash: sha256(&record_bytes),
            prev_hash: previous_hash,
            format_version: 1,
            created_at_unix_micros: accepted_at_micros,
            system_uid: system_user_id.to_string(),
        },
        system_signer,
    );

    let integrity_id: i64 = transaction
        .query_one(
            "INSERT INTO catalogue.integrity
                (source_id, source_type, record_hash, prev_hash, chain_hash,
                 format_version, created_at, system_signature, system_uid)
             VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8)
             RETURNING integrity_id",
            &[
                &manifest.source.source_id,
                &manifest.source.source_type,
                &signed_integrity.envelope.record_hash.to_string(),
                &signed_integrity
                    .envelope
                    .prev_hash
                    .map(|hash| hash.to_string()),
                &signed_integrity.chain_hash.to_string(),
                &accepted_at,
                &&signed_integrity.system_signature[..],
                &system_user_id,
            ],
        )
        .map_err(IngestError::Database)?
        .get(0);
    Ok((integrity_id, signed_integrity.chain_hash.to_string()))
}

fn validate_manifest(manifest: &FidbfIngestManifest) -> Result<(), IngestError> {
    require_nonempty("source.name", &manifest.source.name)?;
    require_nonempty("source.source_type", &manifest.source.source_type)?;
    require_nonempty("fidbf.storage_path", &manifest.fidbf.storage_path)?;
    if !manifest.source.source_type.eq_ignore_ascii_case("FIDBF") {
        return Err(IngestError::Validation(
            "the first ingestion adapter accepts source_type FIDBF only".into(),
        ));
    }
    if manifest.binary.size_bytes < 0
        || manifest.functions.iter().any(|function| {
            function.file_offset.is_some_and(|value| value < 0)
                || function.size_bytes.is_some_and(|value| value < 0)
        })
    {
        return Err(IngestError::Validation(
            "byte sizes and offsets must not be negative".into(),
        ));
    }
    validate_decimal("binary.entry_point", manifest.binary.entry_point.as_deref())?;
    validate_decimal("binary.image_base", manifest.binary.image_base.as_deref())?;
    for function in &manifest.functions {
        validate_decimal(
            "function.virtual_address",
            function.virtual_address.as_deref(),
        )?;
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), IngestError> {
    if value.trim().is_empty() {
        return Err(IngestError::Validation(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn validate_decimal(field: &str, value: Option<&str>) -> Result<(), IngestError> {
    if value
        .is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(IngestError::Validation(format!(
            "{field} must contain unsigned decimal digits"
        )));
    }
    Ok(())
}

fn prepare_submission(
    manifest: &FidbfIngestManifest,
    object_path: &Path,
) -> Result<PreparedSubmission, IngestError> {
    let claimed_sha256 = Digest32::from_str(manifest.fidbf.sha256.as_str())
        .map_err(|_| IngestError::Validation("invalid FIDBF SHA-256".into()))?;
    let claimed_md5 = parse_md5(manifest.fidbf.md5.as_str())?;
    let file = File::open(object_path).map_err(|source| IngestError::ObjectOpen {
        path: object_path.to_path_buf(),
        source,
    })?;
    verify_reader(file, claimed_sha256, claimed_md5).map_err(IngestError::ObjectVerification)?;

    let source_bytes = canonical_source(manifest);
    let batch_bytes = canonical_batch(manifest);
    let fidbf_bytes = canonical_fidbf(manifest);
    let batch_sha256 = sha256(&batch_bytes);
    let batch_md5 = CompatibilityMd5::from_bytes(Md5::digest(&batch_bytes).into());

    Ok(PreparedSubmission {
        source_bytes,
        batch_bytes,
        fidbf_bytes,
        batch_sha256,
        batch_md5,
    })
}

fn canonical_source(manifest: &FidbfIngestManifest) -> Vec<u8> {
    let ecological = manifest.source.is_ecological.map_or(2, u8::from);
    let reference = encode_optional(manifest.source.reference.as_deref());
    let snapshot = encode_optional(manifest.source.snapshot_version.as_deref());
    encode_fields(
        SOURCE_RECORD_DOMAIN,
        &[
            manifest.source.source_id.as_bytes(),
            manifest.source.name.as_bytes(),
            manifest.source.source_type.as_bytes(),
            &reference,
            &snapshot,
            &manifest
                .source
                .retrieved_at
                .timestamp_micros()
                .to_be_bytes(),
            &[ecological],
            manifest.analyst_user_id.as_bytes(),
        ],
    )
}

fn canonical_batch(manifest: &FidbfIngestManifest) -> Vec<u8> {
    let mut functions = manifest.functions.clone();
    functions.sort_by_key(|function| function.function_id);
    let binary = canonical_binary(manifest);
    let fields = std::iter::once(binary)
        .chain(
            functions
                .iter()
                .map(|function| canonical_function(manifest, function)),
        )
        .collect::<Vec<_>>();
    let references = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    encode_fields(BATCH_MANIFEST_DOMAIN, &references)
}

fn canonical_binary(manifest: &FidbfIngestManifest) -> Vec<u8> {
    let binary = &manifest.binary;
    let values = [
        encode_optional(binary.original_filename.as_deref()),
        encode_optional(binary.format.as_deref()),
        encode_optional(binary.architecture.as_deref()),
        encode_optional_i16(binary.bit_width),
        encode_optional(binary.endianness.as_deref()),
        encode_optional(binary.platform.as_deref()),
        encode_optional(binary.abi.as_deref()),
        encode_optional(binary.object_type.as_deref()),
        encode_optional(binary.entry_point.as_deref()),
        encode_optional(binary.image_base.as_deref()),
        encode_optional(binary.build_id.as_deref()),
        encode_optional_bool(binary.is_stripped),
        encode_optional(binary.compiler.as_deref()),
        encode_optional(binary.version.as_deref()),
    ];
    encode_fields(
        BINARY_RECORD_DOMAIN,
        &[
            binary.binary_id.as_bytes(),
            manifest.batch.batch_id.as_bytes(),
            binary.content_sha256.as_str().as_bytes(),
            binary.content_md5.as_str().as_bytes(),
            &binary.size_bytes.to_be_bytes(),
            &values[0],
            &values[1],
            &values[2],
            &values[3],
            &values[4],
            &values[5],
            &values[6],
            &values[7],
            &values[8],
            &values[9],
            &values[10],
            &values[11],
            &values[12],
            &values[13],
            manifest.analyst_user_id.as_bytes(),
            manifest.source.source_id.as_bytes(),
        ],
    )
}

fn canonical_function(manifest: &FidbfIngestManifest, function: &FunctionInput) -> Vec<u8> {
    let values = [
        encode_optional(function.name.as_deref()),
        encode_optional_i64(function.file_offset),
        encode_optional(function.virtual_address.as_deref()),
        encode_optional_i64(function.size_bytes),
        encode_optional(function.section_name.as_deref()),
        encode_optional(function.symbol_name.as_deref()),
        encode_optional(function.mangled_name.as_deref()),
        encode_optional(function.demangled_name.as_deref()),
    ];
    encode_fields(
        FUNCTION_RECORD_DOMAIN,
        &[
            function.function_id.as_bytes(),
            &values[0],
            manifest.binary.binary_id.as_bytes(),
            manifest.fidbf.fidbf_id.as_bytes(),
            function.full_hash.as_str().as_bytes(),
            function.specific_hash.as_str().as_bytes(),
            &values[1],
            &values[2],
            &values[3],
            &values[4],
            &values[5],
            &values[6],
            &values[7],
            &[u8::from(function.is_import)],
            &[u8::from(function.is_export)],
            &[u8::from(function.is_thunk)],
        ],
    )
}

fn canonical_fidbf(manifest: &FidbfIngestManifest) -> Vec<u8> {
    encode_fields(
        FIDBF_RECORD_DOMAIN,
        &[
            manifest.fidbf.fidbf_id.as_bytes(),
            manifest.binary.binary_id.as_bytes(),
            manifest.fidbf.storage_path.as_bytes(),
            manifest.fidbf.sha256.as_str().as_bytes(),
            manifest.fidbf.md5.as_str().as_bytes(),
            manifest.analyst_user_id.as_bytes(),
            manifest.source.source_id.as_bytes(),
        ],
    )
}

fn encode_optional(value: Option<&str>) -> Vec<u8> {
    value.map_or_else(
        || vec![0],
        |value| {
            let mut encoded = Vec::with_capacity(value.len() + 1);
            encoded.push(1);
            encoded.extend_from_slice(value.as_bytes());
            encoded
        },
    )
}

fn encode_optional_i16(value: Option<i16>) -> Vec<u8> {
    value.map_or_else(
        || vec![0],
        |value| [vec![1], value.to_be_bytes().to_vec()].concat(),
    )
}

fn encode_optional_i64(value: Option<i64>) -> Vec<u8> {
    value.map_or_else(
        || vec![0],
        |value| [vec![1], value.to_be_bytes().to_vec()].concat(),
    )
}

fn encode_optional_bool(value: Option<bool>) -> Vec<u8> {
    value.map_or_else(|| vec![0], |value| vec![1, u8::from(value)])
}

fn parse_md5(value: &str) -> Result<CompatibilityMd5, IngestError> {
    if value.len() != 32 {
        return Err(IngestError::Validation("invalid FIDBF MD5".into()));
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| IngestError::Validation("invalid FIDBF MD5".into()))?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| IngestError::Validation("invalid FIDBF MD5".into()))?;
    }
    Ok(CompatibilityMd5::from_bytes(bytes))
}

fn verify_database_identity(
    transaction: &mut Transaction<'_>,
    user_id: Uuid,
    expected_owner: &str,
    expected_role: Option<&str>,
    expected_public_key: Option<&[u8; 32]>,
) -> Result<[u8; 32], IngestError> {
    let row = transaction
        .query_opt(
            "SELECT public_key, role::text, owner_type::text,
                    catalogue.account_is_revoked($1)
             FROM catalogue.user_public WHERE user_id = $1",
            &[&user_id],
        )
        .map_err(IngestError::Database)?
        .ok_or(IngestError::UnknownIdentity(user_id))?;
    let public_key: Vec<u8> = row.get(0);
    let role: Option<String> = row.get(1);
    let owner: String = row.get(2);
    let revoked: bool = row.get(3);
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| IngestError::MalformedPublicKey(user_id))?;
    if expected_public_key.is_some_and(|expected| public_key != *expected) {
        return Err(IngestError::IdentityKeyMismatch(user_id));
    }
    if owner != expected_owner || role.as_deref() != expected_role {
        return Err(IngestError::IdentityKindMismatch(user_id));
    }
    if revoked {
        return Err(IngestError::RevokedIdentity(user_id));
    }
    Ok(public_key)
}

fn verify_analyst_signatures(
    public_key: &[u8; 32],
    prepared: &PreparedSubmission,
    signatures: &AnalystSignatures,
) -> Result<(), IngestError> {
    let values = [
        (
            "source",
            SOURCE_SIGNATURE_DOMAIN,
            sha256(&prepared.source_bytes),
            signatures.source.as_bytes(),
        ),
        (
            "batch",
            BATCH_SIGNATURE_DOMAIN,
            prepared.batch_sha256,
            signatures.batch.as_bytes(),
        ),
        (
            "FIDBF",
            FIDBF_SIGNATURE_DOMAIN,
            sha256(&prepared.fidbf_bytes),
            signatures.fidbf.as_bytes(),
        ),
    ];
    for (name, domain, digest, signature) in values {
        verify_digest_signature(public_key, domain, &digest, signature)
            .map_err(|_| IngestError::InvalidAnalystSignature(name))?;
    }
    Ok(())
}

fn insert_authoritative_rows(
    transaction: &mut Transaction<'_>,
    manifest: &FidbfIngestManifest,
    prepared: &PreparedSubmission,
    signatures: &AnalystSignatures,
    accepted_at: DateTime<Utc>,
) -> Result<(), IngestError> {
    insert_source_and_batch(transaction, manifest, prepared, signatures, accepted_at)?;
    insert_binary_and_fidbf(transaction, manifest, signatures, accepted_at)?;
    insert_functions(transaction, manifest)
}

fn insert_source_and_batch(
    transaction: &mut Transaction<'_>,
    manifest: &FidbfIngestManifest,
    prepared: &PreparedSubmission,
    signatures: &AnalystSignatures,
    accepted_at: DateTime<Utc>,
) -> Result<(), IngestError> {
    transaction
        .execute(
            "INSERT INTO catalogue.source
                (source_id, name, source_type, reference, snapshot_version,
                 retrieved_at, is_ecological, submitted_by_analyst_id, signature)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &manifest.source.source_id,
                &manifest.source.name,
                &manifest.source.source_type,
                &manifest.source.reference,
                &manifest.source.snapshot_version,
                &manifest.source.retrieved_at,
                &manifest.source.is_ecological,
                &manifest.analyst_user_id,
                &&signatures.source.as_bytes()[..],
            ],
        )
        .map_err(IngestError::Database)?;

    transaction
        .execute(
            "INSERT INTO catalogue.batch
                (batch_id, md5, content_sha256, created_at, analyst_user_id, signature)
             VALUES ($1,$2,$3,$4,$5,$6)",
            &[
                &manifest.batch.batch_id,
                &prepared.batch_md5.to_string(),
                &prepared.batch_sha256.to_string(),
                &accepted_at,
                &manifest.analyst_user_id,
                &&signatures.batch.as_bytes()[..],
            ],
        )
        .map_err(IngestError::Database)?;
    Ok(())
}

fn insert_binary_and_fidbf(
    transaction: &mut Transaction<'_>,
    manifest: &FidbfIngestManifest,
    signatures: &AnalystSignatures,
    accepted_at: DateTime<Utc>,
) -> Result<(), IngestError> {
    let binary = &manifest.binary;
    transaction
        .execute(
            "INSERT INTO catalogue.binary_record
                (binary_id, batch_id, content_sha256, content_md5, size_bytes,
                 original_filename, format, architecture, bit_width, endianness,
                 platform, abi, object_type, entry_point, image_base, build_id,
                 is_stripped, compiler, created_at, created_by, version, source_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
                     CAST($14 AS text)::numeric, CAST($15 AS text)::numeric,
                     $16,$17,$18,$19,$20,$21,$22)",
            &[
                &binary.binary_id,
                &manifest.batch.batch_id,
                &binary.content_sha256.as_str(),
                &binary.content_md5.as_str(),
                &binary.size_bytes,
                &binary.original_filename,
                &binary.format,
                &binary.architecture,
                &binary.bit_width,
                &binary.endianness,
                &binary.platform,
                &binary.abi,
                &binary.object_type,
                &binary.entry_point,
                &binary.image_base,
                &binary.build_id,
                &binary.is_stripped,
                &binary.compiler,
                &accepted_at,
                &manifest.analyst_user_id,
                &binary.version,
                &manifest.source.source_id,
            ],
        )
        .map_err(IngestError::Database)?;

    transaction
        .execute(
            "INSERT INTO catalogue.fidbf
                (fidbf_id, binary_id, storage_path, sha256, md5, created_at,
                 submitted_by_user_id, signature, source_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &manifest.fidbf.fidbf_id,
                &binary.binary_id,
                &manifest.fidbf.storage_path,
                &manifest.fidbf.sha256.as_str(),
                &manifest.fidbf.md5.as_str(),
                &accepted_at,
                &manifest.analyst_user_id,
                &&signatures.fidbf.as_bytes()[..],
                &manifest.source.source_id,
            ],
        )
        .map_err(IngestError::Database)?;
    Ok(())
}

fn insert_functions(
    transaction: &mut Transaction<'_>,
    manifest: &FidbfIngestManifest,
) -> Result<(), IngestError> {
    let binary = &manifest.binary;
    for function in &manifest.functions {
        transaction
            .execute(
                "INSERT INTO catalogue.function_record
                    (function_id, name, binary_id, fidbf_id, full_hash, specific_hash,
                     file_offset, virtual_address, size_bytes, section_name, symbol_name,
                     mangled_name, demangled_name, is_import, is_export, is_thunk)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,CAST($8 AS text)::numeric,$9,$10,$11,$12,$13,$14,$15,$16)",
                &[
                    &function.function_id,
                    &function.name,
                    &binary.binary_id,
                    &manifest.fidbf.fidbf_id,
                    &function.full_hash.as_str(),
                    &function.specific_hash.as_str(),
                    &function.file_offset,
                    &function.virtual_address,
                    &function.size_bytes,
                    &function.section_name,
                    &function.symbol_name,
                    &function.mangled_name,
                    &function.demangled_name,
                    &function.is_import,
                    &function.is_export,
                    &function.is_thunk,
                ],
            )
            .map_err(IngestError::Database)?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("invalid manifest: {0}")]
    Validation(String),
    #[error("cannot open FIDBF object {path}: {source}")]
    ObjectOpen {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("FIDBF object verification failed: {0}")]
    ObjectVerification(VerifyError),
    #[error("PostgreSQL operation failed: {0}")]
    Database(postgres::Error),
    #[error("database identity does not exist: {0}")]
    UnknownIdentity(Uuid),
    #[error("loaded private key does not match database identity {0}")]
    IdentityKeyMismatch(Uuid),
    #[error("database identity has a malformed Ed25519 public key: {0}")]
    MalformedPublicKey(Uuid),
    #[error("analyst {0} signature is invalid")]
    InvalidAnalystSignature(&'static str),
    #[error("database identity has the wrong role or owner type: {0}")]
    IdentityKindMismatch(Uuid),
    #[error("database identity is revoked: {0}")]
    RevokedIdentity(Uuid),
    #[error("database clock produced an out-of-range timestamp: {0}")]
    TimestampOutOfRange(i64),
    #[error("existing integrity chain tip is malformed")]
    MalformedChainTip,
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use relic_domain::{FidHash, Md5Hex, Sha256Hex};
    use tempfile::NamedTempFile;

    use super::*;

    fn manifest(sha: &str, md5: &str) -> FidbfIngestManifest {
        FidbfIngestManifest {
            analyst_user_id: Uuid::from_u128(1),
            source: SourceInput {
                source_id: Uuid::from_u128(2),
                name: "test source".into(),
                source_type: "FIDBF".into(),
                reference: None,
                snapshot_version: Some("v1".into()),
                retrieved_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
                is_ecological: Some(false),
            },
            batch: BatchInput {
                batch_id: Uuid::from_u128(3),
            },
            binary: BinaryInput {
                binary_id: Uuid::from_u128(4),
                content_sha256: Sha256Hex::new("1".repeat(64)).unwrap(),
                content_md5: Md5Hex::new("2".repeat(32)).unwrap(),
                size_bytes: 123,
                original_filename: Some("example.bin".into()),
                format: Some("ELF".into()),
                architecture: Some("x86_64".into()),
                bit_width: Some(64),
                endianness: Some("little".into()),
                platform: Some("linux".into()),
                abi: None,
                object_type: None,
                entry_point: Some("4096".into()),
                image_base: Some("0".into()),
                build_id: None,
                is_stripped: Some(false),
                compiler: Some("gcc".into()),
                version: None,
            },
            fidbf: FidbfInput {
                fidbf_id: Uuid::from_u128(5),
                storage_path: "objects/example.fidbf".into(),
                sha256: Sha256Hex::new(sha).unwrap(),
                md5: Md5Hex::new(md5).unwrap(),
            },
            functions: vec![
                FunctionInput {
                    function_id: Uuid::from_u128(7),
                    name: Some("second".into()),
                    full_hash: FidHash::new("0123456789abcdef").unwrap(),
                    specific_hash: FidHash::new("fedcba9876543210").unwrap(),
                    file_offset: Some(64),
                    virtual_address: Some("4160".into()),
                    size_bytes: Some(32),
                    section_name: Some(".text".into()),
                    symbol_name: None,
                    mangled_name: None,
                    demangled_name: None,
                    is_import: false,
                    is_export: false,
                    is_thunk: false,
                },
                FunctionInput {
                    function_id: Uuid::from_u128(6),
                    name: Some("first".into()),
                    full_hash: FidHash::new("aaaaaaaaaaaaaaaa").unwrap(),
                    specific_hash: FidHash::new("bbbbbbbbbbbbbbbb").unwrap(),
                    file_offset: Some(0),
                    virtual_address: Some("4096".into()),
                    size_bytes: Some(64),
                    section_name: Some(".text".into()),
                    symbol_name: None,
                    mangled_name: None,
                    demangled_name: None,
                    is_import: false,
                    is_export: true,
                    is_thunk: false,
                },
            ],
        }
    }

    fn object_and_manifest() -> (NamedTempFile, FidbfIngestManifest) {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"opaque fidbf").unwrap();
        let bytes = std::fs::read(file.path()).unwrap();
        let sha = sha256(&bytes).to_string();
        let md5 = CompatibilityMd5::from_bytes(Md5::digest(&bytes).into()).to_string();
        let manifest = manifest(&sha, &md5);
        (file, manifest)
    }

    #[test]
    fn batch_manifest_is_independent_of_function_input_order() {
        let (_file, first) = object_and_manifest();
        let mut second = first.clone();
        second.functions.reverse();
        assert_eq!(canonical_batch(&first), canonical_batch(&second));
    }

    #[test]
    fn client_signing_verifies_object_and_signs_all_records() {
        let (file, manifest) = object_and_manifest();
        let signer = SystemSigner::from_seed([3; 32]);
        let submission = sign_fidbf_manifest(manifest, file.path(), &signer).unwrap();
        let prepared = prepare_submission(&submission.manifest, file.path()).unwrap();
        verify_analyst_signatures(
            &signer.verifying_key(),
            &prepared,
            &submission.analyst_signatures,
        )
        .unwrap();

        let serialized = serde_json::to_string(&submission).unwrap();
        assert!(!serialized.contains(file.path().to_string_lossy().as_ref()));
        assert!(!serialized.contains("analyst_key"));
    }

    #[test]
    fn preparation_rejects_object_digest_mismatch() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"opaque fidbf").unwrap();
        let result = prepare_submission(&manifest(&"0".repeat(64), &"0".repeat(32)), file.path());
        assert!(matches!(result, Err(IngestError::ObjectVerification(_))));
    }

    #[test]
    fn wrong_analyst_key_cannot_verify_submission() {
        let (file, manifest) = object_and_manifest();
        let signer = SystemSigner::from_seed([3; 32]);
        let submission = sign_fidbf_manifest(manifest, file.path(), &signer).unwrap();
        let prepared = prepare_submission(&submission.manifest, file.path()).unwrap();
        let wrong_key = SystemSigner::from_seed([4; 32]).verifying_key();
        assert!(matches!(
            verify_analyst_signatures(&wrong_key, &prepared, &submission.analyst_signatures),
            Err(IngestError::InvalidAnalystSignature(_))
        ));
    }

    #[test]
    fn invalid_unsigned_decimal_is_rejected() {
        let (_file, mut manifest) = object_and_manifest();
        manifest.binary.entry_point = Some("0x1000".into());
        assert!(matches!(
            validate_manifest(&manifest),
            Err(IngestError::Validation(_))
        ));
    }
}
