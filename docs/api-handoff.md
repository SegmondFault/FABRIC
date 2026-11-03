# API and RBAC handoff — for the Luxembourgeoisie

This is the contract the API must preserve. It describes boundaries, not a
permission to weaken the PostgreSQL constraints or bypass the Rust canonical
encodings.

## Existing POC identity

One throwaway analyst identity is already registered for the initial canary:

- User ID: `744ab74c-f1d6-421a-a417-6030ef9e8606`
- role: `analyst`
- owner type: `human`
- Ed25519 public key: `06a4279b7054e66435315b690286e9df72f098e541f4b70c4d1349b2d28ae1bc`
- SSH fingerprint: `SHA256:hzRFwpshycFFfT3WTWZGJFwbVTZ37hcRDWq8U/oJdUs`

This is an application identity, not a PostgreSQL login. The private key and
its passphrase are deliberately absent from the repository and database.

## BYO-key registration

Analysts create their own Ed25519 keypair locally. RELIC never assigns,
generates, receives or recovers the private half.

The intended multi-party flow is:

1. The prospective analyst requests a short-lived registration challenge.
2. Their client submits the chosen public key, required account details and a
   domain-separated signature over the challenge. This proves possession of
   the matching private key without disclosing it.
3. The request remains pending and cannot sign admissible corpus data.
4. An active moderator reviews it and signs an approve/reject decision.
5. Approval atomically creates the `user_public`/`user_private` account and
   closes the request. Rejection creates no active identity.

Pending requests must not be inserted into `catalogue.user_public`; that table
contains active identities. The RBAC/API work therefore needs an explicit
pending-registration store and signed moderator decision. The exact HTTP route
names are an API choice, but the state transition is not.

One User ID has one permanent public key. If the key is lost or compromised,
the account is revoked and a fresh registration creates a fresh User ID. Names,
email addresses and organisations may repeat; they are not identity keys.

Password handling is analogous only at the secrecy boundary: the server stores
a password hash, never the password. For signatures, the server stores the
public verification key, never the private signing key.

## Submission boundary

An analyst prepares and signs the canonical source, batch and FIDBF records on
their own machine. The API receives only:

- the signed manifest;
- the public User ID;
- the analyst-supplied columns; and
- the separately staged opaque object.

The API must verify proof-of-possession at registration and signatures at every
submission. Authentication alone is not a substitute for verifying the
submission signature.

## Atomic admission

One FIDBF admission is one atomic unit:

`Source + Batch + Binary + FIDBF + Functions + Integrity entry`

The required sequence is:

1. Stage the object under a temporary name outside the database transaction.
2. Hash and verify the exact staged bytes; move them to an immutable
   content-addressed location.
3. Start a serializable database transaction and acquire the single integrity
   sequencer lock.
4. Re-check the analyst identity, role, revocation status, registered public
   key and all analyst signatures inside that transaction.
5. Re-check the integrity-system identity/key and current chain tip.
6. Insert every authoritative row, construct and sign the integrity envelope,
   then insert its chain row.
7. Commit once. Any error rolls back every database row from the attempt.

No authoritative row may be committed with a null, placeholder or pending
digest/signature. A failed transaction may leave only an unreferenced immutable
staged object, which is safe for an audited cleanup.

Exact retries should be idempotent: the same signed request returns the original
committed result; reuse of an ID or idempotency key with different content is a
conflict. The API should never turn a uniqueness error into a partial retry.

MMR checkpoints are asynchronous derivations over committed integrity rows.
They are not part of admission and their delay must never permit an unsigned or
unhashed authoritative row.

## Initial canary scope

Only two deliberately selected legacy batches (the planned batch 0 and batch 1
canaries) should be translated and admitted before the real API is available.
The full corpus waits for the API and object-storage path. Selecting these two
canaries is a separate operator decision; their numeric position is not itself
authority to ingest them.

The legacy translator lives in FIDB-POC-unified, not in this repository.
