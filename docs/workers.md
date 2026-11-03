# Worker boundaries

RELIC keeps evidence-producing duties separate so that each service has a
small, auditable responsibility. PostgreSQL stores and constrains results; it
does not launch worker processes and does not hold a private signing key.

The hashing, integrity-envelope and MMR-frontier libraries are implemented and
covered by deterministic tests. The first FIDBF path includes separate
client-side signing and server-side PostgreSQL ingestion binaries. MMR service
entry points remain fail closed until their database adapters, runtime
identities and key-custody configuration are reviewed. They must not be
admitted merely because their pure calculation code builds.

## FIDBF submission boundary

`relic-sign-fidbf` runs on the analyst's machine. It verifies the exact FIDBF
bytes against the unsigned manifest, loads the analyst's private key locally,
and emits a signed manifest containing no private material or local object
path.

`relic-ingest-fidbf` runs at the trusted ingestion boundary. It receives that
signed manifest plus the separately staged FIDBF, looks up the analyst's public
key in `catalogue.user_public`, verifies all analyst signatures, and admits the
complete source/batch/binary/FIDBF/function set with one integrity entry in one
serializable transaction. Its command line has no analyst-private-key option.

The integrity-system private key is different: it belongs to the narrowly
scoped server worker and signs the RELIC integrity envelope after the analyst
submission has verified.

## Object worker

`relic-object-worker` calculates or independently verifies content digests at
ingestion:

- SHA-256 and compatibility-only MD5 are calculated together from one exact
  byte stream; MD5 is never used as an integrity or signature primitive;

- FIDBF and provenance digests cover the exact stored object bytes;
- BSim digests cover the agreed canonical serialization of `object_data`;
- batch digests cover a canonical, deterministically ordered manifest; and
- binary digests are verified while bytes are transiently available, where
  possible. Binary bytes are not retained by RELIC.

An imported historical record whose bytes are unavailable can carry a supplied
digest, but that limitation must remain visible rather than being described as
independently verified.

## Integrity worker

`relic-integrity-worker` serializes the accepted integrity envelope under a
versioned canonical format, calculates `record_hash` and `chain_hash`, signs
that exact envelope with the integrity system identity, and appends one row to
the non-forking integrity chain.

Only one sequencer may append at a time. The worker must lock, re-read the
current chain tip, hash and sign, then insert atomically. It must never repair a
conflict by overwriting existing evidence.

The database transaction is all-or-nothing and uses this order:

1. acquire the integrity-sequencer lock and re-read the tip;
2. insert or verify the authoritative object row;
3. insert any required relationship row, including `function_bsim`;
4. calculate and sign the complete integrity envelope; and
5. insert the integrity row and commit.

Any failure rolls back every database row from that attempt. No authoritative
row may be accepted with a null, placeholder or pending digest/signature.
Object storage is staged separately: upload to a temporary name, hash and
verify it, move it to its immutable content-addressed name, then begin the
database transaction. A failed transaction can therefore leave only an
unreferenced immutable object, which is safe for a later audited cleanup.

## MMR worker

`relic-mmr-worker` consumes ordered integrity-chain rows, performs
domain-separated leaf, internal-node and peak-commitment hashing, and inserts
an immutable signed `mmr_checkpoint`. It does not change the integrity chain.

Only one checkpoint sequencer may advance a format version at a time. The
worker must be able to reconstruct and compare the expected frontier before it
continues from a stored checkpoint.

## Hashing and signing

Hashing and signing are implemented in shared Rust library code so that workers
use identical canonical encodings and test vectors. They are not delegated to
PostgreSQL. PostgreSQL may validate relationships and recompute narrowly
defined checks, but it is not the source of cryptographic truth.

Version 1 uses SHA-256 and Ed25519. Canonical hashes use explicit domain tags,
big-endian fixed-width integers and length-prefixed variable-width fields.
Changing an algorithm, field set, field order, encoding or domain tag requires
a new format version and test vectors.

The private system keys remain outside PostgreSQL and outside this repository,
readable only by the relevant unprivileged service account. Each producing
worker signs its own canonical result:

- the integrity worker signs the complete integrity envelope, including the
  preceding chain hash; and
- the MMR worker signs the checkpoint format version, covered extent, ordered
  peaks, commitment, system identity and explicit timestamp.

The corresponding public key remains in `catalogue.user_public`. Integrity and
MMR duties should use distinct system accounts and keys so either authority can
be replaced without impersonating the other.

For every analyst- or moderator-signed operation, the worker must resolve the
claimed User ID to its immutable `catalogue.user_public.public_key` and verify
the operation's domain-separated canonical payload with that exact key. It
must never trust a request-supplied verification key, search for some other key
that happens to verify, or treat login authentication as proof that a payload
was signed. Identity, active role, registered key, payload and signature are a
single fail-closed admission check performed inside the transaction.

## Admission and checkpoint timing

Integrity admission is synchronous and complete before a record is accepted.
MMR construction is derived, asynchronous work: it consumes only committed
integrity entries, and an MMR delay never permits an unhashed or unsigned
authoritative row. A checkpoint is inserted atomically after its frontier has
been independently reconstructed and signed.
