-- RELIC (Reproducible Evidence for Lineage and Integrity of Code), version 1.
-- PostgreSQL 15+.
--
-- Trust model:
--   * one immutable public key per account;
--   * a lost or compromised key requires a new account;
--   * approved user revocations prevent future submissions but preserve old
--     accounts and keys for historical verification;
--   * Binary and Function rows are covered by the signature on their Batch;
--   * independently submitted objects and later moderation actions carry their
--     own signatures;
--   * signature verification is performed by the application against
--     user_public.public_key. The database enforces actor identity and role.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS catalogue;
SET search_path = catalogue, public;

CREATE DOMAIN sha256_hex AS text
    CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN md5_hex AS text
    CHECK (VALUE ~ '^[0-9a-f]{32}$');

CREATE TYPE account_role AS ENUM (
    'viewer',
    'analyst',
    'moderator'
);

CREATE TYPE account_owner_type AS ENUM (
    'human',
    'system'
);

CREATE TYPE corpus_target_type AS ENUM (
    'user',
    'source',
    'batch',
    'binary',
    'function',
    'fidbf',
    'bsim',
    'provenance',
    'classification',
    'flag'
);

CREATE TYPE revocation_decision AS ENUM (
    'approved',
    'rejected'
);

CREATE TABLE user_public (
    user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key bytea NOT NULL CHECK (octet_length(public_key) > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    role account_role,
    owner_type account_owner_type NOT NULL DEFAULT 'human',
    CHECK (
        (owner_type = 'human' AND role IS NOT NULL)
        OR (owner_type = 'system' AND role IS NULL)
    )
);

COMMENT ON TABLE user_public IS
    'Public account identity. A UserID has one permanent public key.';
COMMENT ON COLUMN user_public.public_key IS
    'Verification key for every signature made by this account. Immutable.';

CREATE TABLE user_private (
    user_id uuid PRIMARY KEY
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (btrim(name) <> ''),
    organisation text,
    email text NOT NULL CHECK (btrim(email) <> ''),
    password_hash bytea NOT NULL CHECK (octet_length(password_hash) > 0),
    password_salt bytea NOT NULL CHECK (octet_length(password_salt) > 0)
);

COMMENT ON TABLE user_private IS
    'Private account data. Names, email addresses and organisations are not identities and may repeat across accounts.';

CREATE TABLE source (
    source_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (btrim(name) <> ''),
    source_type text NOT NULL CHECK (btrim(source_type) <> ''),
    reference text,
    snapshot_version text,
    retrieved_at timestamptz NOT NULL,
    is_ecological boolean,
    submitted_by_analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0)
);

COMMENT ON COLUMN source.reference IS
    'Optional human-readable source reference; it is not required to be a URI.';
COMMENT ON COLUMN source.is_ecological IS
    'TRUE for ecological/real-world input, FALSE for artificial/synthetic input, NULL when unknown.';

CREATE TABLE batch (
    batch_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    md5 md5_hex NOT NULL,
    content_sha256 sha256_hex NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    analyst_user_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0)
);

COMMENT ON COLUMN batch.content_sha256 IS
    'SHA-256 of the canonical, deterministically ordered manifest of every Binary and Function row in this batch.';
COMMENT ON COLUMN batch.md5 IS
    'Compatibility digest of the same canonical batch manifest.';

CREATE TABLE binary_record (
    binary_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id uuid NOT NULL
        REFERENCES batch(batch_id) ON DELETE RESTRICT,
    content_sha256 sha256_hex NOT NULL,
    content_md5 md5_hex NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    original_filename text,
    format text,
    architecture text,
    bit_width smallint CHECK (bit_width IS NULL OR bit_width > 0),
    endianness text,
    platform text,
    abi text,
    object_type text,
    entry_point numeric(20, 0) CHECK (entry_point IS NULL OR entry_point >= 0),
    image_base numeric(20, 0) CHECK (image_base IS NULL OR image_base >= 0),
    build_id text,
    is_stripped boolean,
    compiler text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid REFERENCES user_public(user_id) ON DELETE RESTRICT,
    version text,
    source_id uuid NOT NULL
        REFERENCES source(source_id) ON DELETE RESTRICT
);

COMMENT ON TABLE binary_record IS
    'Binary metadata and digests only. Binary bytes are not stored.';

CREATE TABLE fidbf (
    fidbf_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    binary_id uuid NOT NULL
        REFERENCES binary_record(binary_id) ON DELETE RESTRICT,
    storage_path text NOT NULL CHECK (btrim(storage_path) <> ''),
    sha256 sha256_hex NOT NULL,
    md5 md5_hex NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_by_user_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    source_id uuid NOT NULL
        REFERENCES source(source_id) ON DELETE RESTRICT,
    UNIQUE (fidbf_id, binary_id)
);

COMMENT ON TABLE fidbf IS
    'One opaque FIDBF object for a Binary. Its contents are not assumed to be queryable by this schema.';

CREATE TABLE function_record (
    function_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text,
    binary_id uuid NOT NULL
        REFERENCES binary_record(binary_id) ON DELETE RESTRICT,
    fidbf_id uuid,
    full_hash text NOT NULL CHECK (btrim(full_hash) <> ''),
    specific_hash text NOT NULL CHECK (btrim(specific_hash) <> ''),
    file_offset bigint CHECK (file_offset IS NULL OR file_offset >= 0),
    virtual_address numeric(20, 0)
        CHECK (virtual_address IS NULL OR virtual_address >= 0),
    size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes >= 0),
    section_name text,
    symbol_name text,
    mangled_name text,
    demangled_name text,
    is_import boolean NOT NULL DEFAULT false,
    is_export boolean NOT NULL DEFAULT false,
    is_thunk boolean NOT NULL DEFAULT false,
    UNIQUE (function_id, binary_id),
    FOREIGN KEY (fidbf_id, binary_id)
        REFERENCES fidbf(fidbf_id, binary_id) ON DELETE RESTRICT
);

COMMENT ON TABLE function_record IS
    'Function metadata covered by its Binary Batch signature. FIDBF_ID is optional because Functions may arrive without an FIDBF.';

CREATE TABLE bsim (
    bsim_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_data jsonb NOT NULL,
    sha256 sha256_hex NOT NULL,
    md5 md5_hex NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_by_user_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    source_id uuid NOT NULL
        REFERENCES source(source_id) ON DELETE RESTRICT
);

COMMENT ON TABLE bsim IS
    'One inspectable BSim object. Function associations are recorded separately so one object may describe multiple Function occurrences.';
COMMENT ON COLUMN bsim.sha256 IS
    'Digest of the agreed canonical serialization of object_data, not PostgreSQL physical storage bytes.';

CREATE TABLE function_bsim (
    function_bsim_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    function_id uuid NOT NULL,
    binary_id uuid NOT NULL,
    bsim_id uuid NOT NULL
        REFERENCES bsim(bsim_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (function_id, binary_id)
        REFERENCES function_record(function_id, binary_id) ON DELETE RESTRICT,
    UNIQUE (function_id, bsim_id)
);

COMMENT ON TABLE function_bsim IS
    'Many-to-many membership between an inspectable BSim object and exact Function occurrences. Binary_ID enforces same-occurrence context through the composite Function foreign key.';

CREATE TABLE provenance (
    provenance_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fidbf_id uuid REFERENCES fidbf(fidbf_id) ON DELETE RESTRICT,
    bsim_id uuid REFERENCES bsim(bsim_id) ON DELETE RESTRICT,
    binary_id uuid REFERENCES binary_record(binary_id) ON DELETE RESTRICT,
    schema_name text,
    schema_version text,
    storage_path text NOT NULL CHECK (btrim(storage_path) <> ''),
    sha256 sha256_hex NOT NULL,
    md5 md5_hex NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_by_user_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    source_id uuid NOT NULL
        REFERENCES source(source_id) ON DELETE RESTRICT,
    CHECK (num_nonnulls(fidbf_id, bsim_id, binary_id) >= 1)
);

COMMENT ON TABLE provenance IS
    'Path and digests for user-schema provenance JSON used for external reproducibility verification.';

CREATE TABLE revocation (
    revocation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    analyst_request_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    moderator_id uuid REFERENCES user_public(user_id) ON DELETE RESTRICT,
    target_type corpus_target_type NOT NULL,
    target_id uuid NOT NULL,
    reason text NOT NULL CHECK (btrim(reason) <> ''),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    decision revocation_decision,
    decided_at timestamptz,
    request_signature bytea NOT NULL CHECK (octet_length(request_signature) > 0),
    decision_signature bytea,
    CHECK (
        (
            decision IS NULL
            AND moderator_id IS NULL
            AND decided_at IS NULL
            AND decision_signature IS NULL
        )
        OR
        (
            decision IS NOT NULL
            AND moderator_id IS NOT NULL
            AND decided_at IS NOT NULL
            AND decision_signature IS NOT NULL
            AND octet_length(decision_signature) > 0
        )
    ),
    CHECK (decided_at IS NULL OR decided_at >= requested_at)
);

COMMENT ON TABLE revocation IS
    'Only Analysts request revocation; only Moderators decide it. target_type=user revokes an account.';

CREATE TABLE flag (
    flag_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    viewer_request_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    note text NOT NULL CHECK (btrim(note) <> ''),
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    target_type corpus_target_type NOT NULL,
    target_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE flag_response (
    flag_response_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    analyst_request_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    note text NOT NULL CHECK (btrim(note) <> ''),
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    flag_id uuid NOT NULL
        REFERENCES flag(flag_id) ON DELETE RESTRICT
);

COMMENT ON TABLE flag_response IS
    'An independently identified Analyst response pointing to its Flag. Multiple responses per Flag are allowed.';

CREATE TABLE classification (
    classification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_type corpus_target_type NOT NULL
        CHECK (target_type IN ('binary', 'function')),
    target_id uuid NOT NULL,
    label text NOT NULL CHECK (btrim(label) <> ''),
    confidence numeric(5, 4)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    analyst_id uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    evidence jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    misp_universe text,
    misp_uuid uuid,
    signature bytea NOT NULL CHECK (octet_length(signature) > 0)
);

CREATE TABLE integrity (
    integrity_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id uuid NOT NULL
        REFERENCES source(source_id) ON DELETE RESTRICT,
    source_type text NOT NULL CHECK (btrim(source_type) <> ''),
    record_hash sha256_hex NOT NULL,
    prev_hash sha256_hex,
    chain_hash sha256_hex NOT NULL UNIQUE,
    format_version integer NOT NULL CHECK (format_version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    system_signature bytea NOT NULL CHECK (octet_length(system_signature) > 0),
    system_uid uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    CHECK (prev_hash IS NULL OR prev_hash <> chain_hash),
    FOREIGN KEY (prev_hash)
        REFERENCES integrity(chain_hash) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

COMMENT ON TABLE integrity IS
    'System-signed append-only hash chain. source_type is retained in the signed envelope and must match Source.source_type.';

CREATE TABLE mmr_checkpoint (
    mmr_checkpoint_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    last_integrity_id bigint NOT NULL
        REFERENCES integrity(integrity_id) ON DELETE RESTRICT,
    leaf_count bigint NOT NULL CHECK (leaf_count > 0),
    peaks jsonb NOT NULL
        CHECK (jsonb_typeof(peaks) = 'array' AND jsonb_array_length(peaks) > 0),
    commitment sha256_hex NOT NULL,
    format_version integer NOT NULL CHECK (format_version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    system_uid uuid NOT NULL
        REFERENCES user_public(user_id) ON DELETE RESTRICT,
    system_signature bytea NOT NULL CHECK (octet_length(system_signature) > 0),
    UNIQUE (format_version, last_integrity_id),
    UNIQUE (format_version, leaf_count)
);

COMMENT ON TABLE mmr_checkpoint IS
    'Immutable signed MMR checkpoint over the existing integrity hash chain. last_integrity_id identifies the newest covered row; earlier rows are reached through prev_hash.';
COMMENT ON COLUMN mmr_checkpoint.peaks IS
    'Ordered inspectable JSON array of MMR peak heights and hashes used to reproduce the checkpoint commitment.';
COMMENT ON COLUMN mmr_checkpoint.leaf_count IS
    'Number of integrity rows covered from the genesis row through last_integrity_id.';

-- Foreign-key lookup indexes. PostgreSQL does not create these automatically.
CREATE INDEX binary_batch_id_idx ON binary_record(batch_id);
CREATE INDEX binary_source_id_idx ON binary_record(source_id);
CREATE INDEX binary_sha256_idx ON binary_record(content_sha256);
CREATE INDEX binary_md5_idx ON binary_record(content_md5);
CREATE INDEX fidbf_binary_id_idx ON fidbf(binary_id);
CREATE INDEX fidbf_source_id_idx ON fidbf(source_id);
CREATE INDEX fidbf_sha256_idx ON fidbf(sha256);
CREATE INDEX function_binary_id_idx ON function_record(binary_id);
CREATE INDEX function_fidbf_id_idx ON function_record(fidbf_id);
CREATE INDEX function_hashes_idx ON function_record(full_hash, specific_hash);
CREATE INDEX bsim_source_id_idx ON bsim(source_id);
CREATE INDEX bsim_sha256_idx ON bsim(sha256);
CREATE INDEX function_bsim_binary_id_idx ON function_bsim(binary_id);
CREATE INDEX function_bsim_bsim_id_idx ON function_bsim(bsim_id);
CREATE INDEX provenance_fidbf_id_idx ON provenance(fidbf_id);
CREATE INDEX provenance_bsim_id_idx ON provenance(bsim_id);
CREATE INDEX provenance_binary_id_idx ON provenance(binary_id);
CREATE INDEX provenance_source_id_idx ON provenance(source_id);
CREATE INDEX revocation_target_idx ON revocation(target_type, target_id);
CREATE INDEX revocation_account_state_idx
    ON revocation(target_id, decided_at)
    WHERE target_type = 'user' AND decision = 'approved';
CREATE INDEX flag_target_idx ON flag(target_type, target_id);
CREATE INDEX flag_response_flag_id_idx ON flag_response(flag_id);
CREATE INDEX classification_target_idx
    ON classification(target_type, target_id);
CREATE INDEX integrity_source_id_idx ON integrity(source_id);
CREATE INDEX mmr_checkpoint_system_uid_idx ON mmr_checkpoint(system_uid);

-- One global, non-forking integrity chain: one genesis and at most one child
-- for each chain hash.
CREATE UNIQUE INDEX integrity_single_genesis_idx
    ON integrity ((true))
    WHERE prev_hash IS NULL;

CREATE UNIQUE INDEX integrity_single_successor_idx
    ON integrity (prev_hash)
    WHERE prev_hash IS NOT NULL;

CREATE FUNCTION prevent_account_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF NEW.user_id <> OLD.user_id
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.owner_type <> OLD.owner_type THEN
        RAISE EXCEPTION
            'UserID, public key and owner type are immutable; create a new account instead'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER user_public_identity_immutable
BEFORE UPDATE ON user_public
FOR EACH ROW EXECUTE FUNCTION prevent_account_identity_change();

CREATE FUNCTION account_is_revoked(candidate_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = catalogue, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM revocation AS r
        WHERE r.target_type = 'user'
          AND r.target_id = candidate_user_id
          AND r.decision = 'approved'
          AND r.decided_at <= clock_timestamp()
    );
$$;

CREATE FUNCTION require_actor_role()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    actor_id uuid;
    actor_role account_role;
    actor_owner_type account_owner_type;
    required_role account_role := TG_ARGV[1]::account_role;
BEGIN
    actor_id := NULLIF(to_jsonb(NEW) ->> TG_ARGV[0], '')::uuid;

    SELECT role, owner_type
      INTO actor_role, actor_owner_type
      FROM user_public
     WHERE user_id = actor_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown actor %', actor_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF actor_owner_type <> 'human' OR actor_role <> required_role THEN
        RAISE EXCEPTION 'Actor % must have role %', actor_id, required_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF account_is_revoked(actor_id) THEN
        RAISE EXCEPTION 'Actor account % is revoked', actor_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION require_active_human_actor()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    actor_id uuid;
    actor_owner_type account_owner_type;
BEGIN
    actor_id := NULLIF(to_jsonb(NEW) ->> TG_ARGV[0], '')::uuid;

    SELECT owner_type
      INTO actor_owner_type
      FROM user_public
     WHERE user_id = actor_id;

    IF NOT FOUND OR actor_owner_type <> 'human' THEN
        RAISE EXCEPTION 'Actor % must be a human account', actor_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF account_is_revoked(actor_id) THEN
        RAISE EXCEPTION 'Actor account % is revoked', actor_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_revocation_actors()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    requester_role account_role;
    requester_owner account_owner_type;
    moderator_role account_role;
    moderator_owner account_owner_type;
BEGIN
    SELECT role, owner_type
      INTO requester_role, requester_owner
      FROM user_public
     WHERE user_id = NEW.analyst_request_id;

    IF NOT FOUND
       OR requester_owner <> 'human'
       OR requester_role <> 'analyst'
       OR account_is_revoked(NEW.analyst_request_id) THEN
        RAISE EXCEPTION 'Revocation requester must be an active Analyst'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.decision IS NOT NULL THEN
        SELECT role, owner_type
          INTO moderator_role, moderator_owner
          FROM user_public
         WHERE user_id = NEW.moderator_id;

        IF NOT FOUND
           OR moderator_owner <> 'human'
           OR moderator_role <> 'moderator'
           OR account_is_revoked(NEW.moderator_id) THEN
            RAISE EXCEPTION 'Revocation decision requires an active Moderator'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION target_exists(
    candidate_type corpus_target_type,
    candidate_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    RETURN CASE candidate_type
        WHEN 'user' THEN EXISTS (
            SELECT 1 FROM user_public WHERE user_id = candidate_id
        )
        WHEN 'source' THEN EXISTS (
            SELECT 1 FROM source WHERE source_id = candidate_id
        )
        WHEN 'batch' THEN EXISTS (
            SELECT 1 FROM batch WHERE batch_id = candidate_id
        )
        WHEN 'binary' THEN EXISTS (
            SELECT 1 FROM binary_record WHERE binary_id = candidate_id
        )
        WHEN 'function' THEN EXISTS (
            SELECT 1 FROM function_record WHERE function_id = candidate_id
        )
        WHEN 'fidbf' THEN EXISTS (
            SELECT 1 FROM fidbf WHERE fidbf_id = candidate_id
        )
        WHEN 'bsim' THEN EXISTS (
            SELECT 1 FROM bsim WHERE bsim_id = candidate_id
        )
        WHEN 'provenance' THEN EXISTS (
            SELECT 1 FROM provenance WHERE provenance_id = candidate_id
        )
        WHEN 'classification' THEN EXISTS (
            SELECT 1 FROM classification WHERE classification_id = candidate_id
        )
        WHEN 'flag' THEN EXISTS (
            SELECT 1 FROM flag WHERE flag_id = candidate_id
        )
    END;
END;
$$;

CREATE FUNCTION validate_polymorphic_target()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
BEGIN
    IF NOT target_exists(NEW.target_type, NEW.target_id) THEN
        RAISE EXCEPTION 'Target %.% does not exist', NEW.target_type, NEW.target_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_provenance_target_consistency()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    linked_binary_id uuid;
BEGIN
    IF NEW.fidbf_id IS NOT NULL AND NEW.binary_id IS NOT NULL THEN
        SELECT binary_id INTO linked_binary_id
          FROM fidbf WHERE fidbf_id = NEW.fidbf_id;
        IF linked_binary_id <> NEW.binary_id THEN
            RAISE EXCEPTION 'Provenance FIDBF and Binary targets disagree'
                USING ERRCODE = 'foreign_key_violation';
        END IF;
    END IF;

    IF NEW.bsim_id IS NOT NULL AND NEW.binary_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
              FROM function_bsim
             WHERE bsim_id = NEW.bsim_id
               AND binary_id = NEW.binary_id
        ) THEN
            RAISE EXCEPTION 'Provenance BSim and Binary targets disagree'
                USING ERRCODE = 'foreign_key_violation';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_integrity_entry()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    actual_source_type text;
    system_owner account_owner_type;
BEGIN
    SELECT source_type INTO actual_source_type
      FROM source WHERE source_id = NEW.source_id;

    IF actual_source_type IS DISTINCT FROM NEW.source_type THEN
        RAISE EXCEPTION 'Integrity source_type must match Source.source_type'
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT owner_type INTO system_owner
      FROM user_public WHERE user_id = NEW.system_uid;

    IF NOT FOUND OR system_owner <> 'system' THEN
        RAISE EXCEPTION 'Integrity system_uid must identify a system account'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF account_is_revoked(NEW.system_uid) THEN
        RAISE EXCEPTION 'Integrity system account % is revoked', NEW.system_uid
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_mmr_checkpoint()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = catalogue, pg_temp
AS $$
DECLARE
    system_owner account_owner_type;
    actual_leaf_count bigint;
    genesis_count bigint;
BEGIN
    SELECT owner_type
      INTO system_owner
      FROM user_public
     WHERE user_id = NEW.system_uid;

    IF NOT FOUND OR system_owner <> 'system' THEN
        RAISE EXCEPTION 'MMR checkpoint system_uid must identify a system account'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF account_is_revoked(NEW.system_uid) THEN
        RAISE EXCEPTION 'MMR checkpoint system account % is revoked', NEW.system_uid
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    WITH RECURSIVE covered AS (
        SELECT
            integrity_id,
            prev_hash,
            ARRAY[integrity_id]::bigint[] AS visited
        FROM integrity
        WHERE integrity_id = NEW.last_integrity_id

        UNION ALL

        SELECT
            parent.integrity_id,
            parent.prev_hash,
            child.visited || parent.integrity_id
        FROM covered AS child
        JOIN integrity AS parent
          ON parent.chain_hash = child.prev_hash
        WHERE NOT parent.integrity_id = ANY(child.visited)
    )
    SELECT
        count(*),
        count(*) FILTER (WHERE prev_hash IS NULL)
      INTO actual_leaf_count, genesis_count
      FROM covered;

    IF genesis_count <> 1 THEN
        RAISE EXCEPTION 'MMR checkpoint must terminate at the integrity genesis row'
            USING ERRCODE = 'check_violation';
    END IF;

    IF actual_leaf_count <> NEW.leaf_count THEN
        RAISE EXCEPTION
            'MMR checkpoint leaf_count % does not match % covered integrity rows',
            NEW.leaf_count,
            actual_leaf_count
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION reject_mmr_checkpoint_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MMR checkpoint rows are immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER source_requires_analyst
BEFORE INSERT OR UPDATE ON source
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'submitted_by_analyst_id', 'analyst'
);

CREATE TRIGGER batch_requires_analyst
BEFORE INSERT OR UPDATE ON batch
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'analyst_user_id', 'analyst'
);

CREATE TRIGGER fidbf_requires_active_submitter
BEFORE INSERT OR UPDATE ON fidbf
FOR EACH ROW EXECUTE FUNCTION require_active_human_actor(
    'submitted_by_user_id'
);

CREATE TRIGGER bsim_requires_active_submitter
BEFORE INSERT OR UPDATE ON bsim
FOR EACH ROW EXECUTE FUNCTION require_active_human_actor(
    'submitted_by_user_id'
);

CREATE TRIGGER provenance_requires_active_submitter
BEFORE INSERT OR UPDATE ON provenance
FOR EACH ROW EXECUTE FUNCTION require_active_human_actor(
    'submitted_by_user_id'
);

CREATE TRIGGER revocation_actor_rules
BEFORE INSERT OR UPDATE ON revocation
FOR EACH ROW EXECUTE FUNCTION validate_revocation_actors();

CREATE TRIGGER revocation_target_must_exist
BEFORE INSERT OR UPDATE OF target_type, target_id ON revocation
FOR EACH ROW EXECUTE FUNCTION validate_polymorphic_target();

CREATE TRIGGER flag_requires_viewer
BEFORE INSERT OR UPDATE ON flag
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'viewer_request_id', 'viewer'
);

CREATE TRIGGER flag_target_must_exist
BEFORE INSERT OR UPDATE OF target_type, target_id ON flag
FOR EACH ROW EXECUTE FUNCTION validate_polymorphic_target();

CREATE TRIGGER flag_response_requires_analyst
BEFORE INSERT OR UPDATE ON flag_response
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'analyst_request_id', 'analyst'
);

CREATE TRIGGER classification_requires_analyst
BEFORE INSERT OR UPDATE ON classification
FOR EACH ROW EXECUTE FUNCTION require_actor_role(
    'analyst_id', 'analyst'
);

CREATE TRIGGER classification_target_must_exist
BEFORE INSERT OR UPDATE OF target_type, target_id ON classification
FOR EACH ROW EXECUTE FUNCTION validate_polymorphic_target();

CREATE TRIGGER provenance_targets_must_agree
BEFORE INSERT OR UPDATE ON provenance
FOR EACH ROW EXECUTE FUNCTION validate_provenance_target_consistency();

CREATE TRIGGER integrity_entry_rules
BEFORE INSERT OR UPDATE ON integrity
FOR EACH ROW EXECUTE FUNCTION validate_integrity_entry();

CREATE TRIGGER mmr_checkpoint_rules
BEFORE INSERT ON mmr_checkpoint
FOR EACH ROW EXECUTE FUNCTION validate_mmr_checkpoint();

CREATE TRIGGER mmr_checkpoint_is_immutable
BEFORE UPDATE OR DELETE ON mmr_checkpoint
FOR EACH ROW EXECUTE FUNCTION reject_mmr_checkpoint_change();

COMMIT;
