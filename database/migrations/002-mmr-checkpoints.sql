-- RELIC migration 002: signed MMR checkpoints over the existing integrity
-- hash chain. The integrity table remains unchanged and authoritative.

\set ON_ERROR_STOP on

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

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
    UNIQUE (format_version, last_integrity_id)
);

COMMENT ON TABLE mmr_checkpoint IS
    'Immutable signed MMR checkpoint over the existing integrity hash chain. last_integrity_id identifies the newest covered row; earlier rows are reached through prev_hash.';
COMMENT ON COLUMN mmr_checkpoint.peaks IS
    'Ordered inspectable JSON array of peak start indexes, heights and hashes used to reproduce the checkpoint commitment.';
COMMENT ON COLUMN mmr_checkpoint.leaf_count IS
    'Number of integrity rows covered from the genesis row through last_integrity_id.';

CREATE INDEX mmr_checkpoint_system_uid_idx
    ON mmr_checkpoint(system_uid);

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

CREATE TRIGGER mmr_checkpoint_rules
BEFORE INSERT ON mmr_checkpoint
FOR EACH ROW EXECUTE FUNCTION validate_mmr_checkpoint();

CREATE FUNCTION reject_mmr_checkpoint_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MMR checkpoint rows are immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER mmr_checkpoint_is_immutable
BEFORE UPDATE OR DELETE ON mmr_checkpoint
FOR EACH ROW EXECUTE FUNCTION reject_mmr_checkpoint_change();

-- relic_owner's existing default privileges grant UPDATE on new tables. This
-- table is append-only evidence, so narrow the application role explicitly.
REVOKE UPDATE ON mmr_checkpoint FROM relic_app;
GRANT SELECT, INSERT ON mmr_checkpoint TO relic_app;
GRANT USAGE, SELECT ON SEQUENCE mmr_checkpoint_mmr_checkpoint_id_seq
    TO relic_app;
GRANT EXECUTE ON FUNCTION validate_mmr_checkpoint() TO relic_app;
GRANT EXECUTE ON FUNCTION reject_mmr_checkpoint_change() TO relic_app;

RESET ROLE;

COMMIT;
