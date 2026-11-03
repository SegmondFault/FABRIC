-- Transactional regression checks for RELIC admission and derived MMR state.
-- Run only against a disposable database; this file rolls back its own data.

\set ON_ERROR_STOP on

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    system_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    bsim_id_value uuid := gen_random_uuid();
    rejected boolean := false;
BEGIN
    BEGIN
        INSERT INTO user_public (user_id, public_key, role, owner_type)
        VALUES
            (analyst_id, '\x01', 'analyst', 'human'),
            (system_id, '\x02', NULL, 'system');

        INSERT INTO source (
            source_id, name, source_type, retrieved_at,
            submitted_by_analyst_id, signature
        ) VALUES (
            source_id_value, 'atomic-rollback-source', 'BSIM', clock_timestamp(),
            analyst_id, '\x03'
        );

        INSERT INTO bsim (
            bsim_id, object_data, sha256, md5, submitted_by_user_id,
            signature, source_id
        ) VALUES (
            bsim_id_value, '{"value":1}', repeat('a', 64), repeat('b', 32),
            analyst_id, '\x04', source_id_value
        );

        -- The trigger must reject this mismatch and the surrounding
        -- subtransaction must remove every earlier row from the attempt.
        INSERT INTO integrity (
            source_id, source_type, record_hash, prev_hash, chain_hash,
            format_version, system_signature, system_uid
        ) VALUES (
            source_id_value, 'FIDBF', repeat('c', 64), NULL, repeat('d', 64),
            1, '\x05', system_id
        );
    EXCEPTION
        WHEN check_violation THEN
            rejected := true;
    END;

    IF NOT rejected THEN
        RAISE EXCEPTION 'invalid integrity source_type was not rejected';
    END IF;
    IF EXISTS (SELECT FROM source WHERE source_id = source_id_value)
        OR EXISTS (SELECT FROM bsim WHERE bsim_id = bsim_id_value)
        OR EXISTS (SELECT FROM user_public WHERE user_id IN (analyst_id, system_id))
    THEN
        RAISE EXCEPTION 'failed admission left partial authoritative rows';
    END IF;
END;
$$;

DO $$
DECLARE
    analyst_id uuid := gen_random_uuid();
    integrity_system_id uuid := gen_random_uuid();
    mmr_system_id uuid := gen_random_uuid();
    source_id_value uuid := gen_random_uuid();
    batch_id_value uuid := gen_random_uuid();
    binary_id_value uuid := gen_random_uuid();
    first_function_id uuid := gen_random_uuid();
    second_function_id uuid := gen_random_uuid();
    bsim_id_value uuid := gen_random_uuid();
    first_integrity_id bigint;
    second_integrity_id bigint;
    checkpoint_id bigint;
    rejected boolean;
BEGIN
    INSERT INTO user_public (user_id, public_key, role, owner_type)
    VALUES
        (analyst_id, '\x11', 'analyst', 'human'),
        (integrity_system_id, '\x12', NULL, 'system'),
        (mmr_system_id, '\x13', NULL, 'system');

    INSERT INTO source (
        source_id, name, source_type, retrieved_at,
        submitted_by_analyst_id, signature
    ) VALUES (
        source_id_value, 'valid-membership-source', 'BSIM', clock_timestamp(),
        analyst_id, '\x14'
    );

    INSERT INTO batch (
        batch_id, md5, content_sha256, analyst_user_id, signature
    ) VALUES (
        batch_id_value, repeat('1', 32), repeat('2', 64), analyst_id, '\x15'
    );

    INSERT INTO binary_record (
        binary_id, batch_id, content_sha256, content_md5, size_bytes,
        created_by, source_id
    ) VALUES (
        binary_id_value, batch_id_value, repeat('3', 64), repeat('4', 32), 16,
        analyst_id, source_id_value
    );

    INSERT INTO function_record (
        function_id, binary_id, full_hash, specific_hash
    ) VALUES
        (first_function_id, binary_id_value, 'full-1', 'specific-1'),
        (second_function_id, binary_id_value, 'full-2', 'specific-2');

    INSERT INTO bsim (
        bsim_id, object_data, sha256, md5, submitted_by_user_id,
        signature, source_id
    ) VALUES (
        bsim_id_value, '{"value":2}', repeat('5', 64), repeat('6', 32),
        analyst_id, '\x16', source_id_value
    );

    INSERT INTO function_bsim (function_id, binary_id, bsim_id)
    VALUES
        (first_function_id, binary_id_value, bsim_id_value),
        (second_function_id, binary_id_value, bsim_id_value);

    IF (SELECT count(*) FROM function_bsim WHERE bsim_id = bsim_id_value) <> 2 THEN
        RAISE EXCEPTION 'one BSim object did not retain both Function memberships';
    END IF;

    INSERT INTO integrity (
        source_id, source_type, record_hash, prev_hash, chain_hash,
        format_version, system_signature, system_uid
    ) VALUES (
        source_id_value, 'BSIM', repeat('7', 64), NULL, repeat('8', 64),
        1, '\x17', integrity_system_id
    ) RETURNING integrity_id INTO first_integrity_id;

    INSERT INTO integrity (
        source_id, source_type, record_hash, prev_hash, chain_hash,
        format_version, system_signature, system_uid
    ) VALUES (
        source_id_value, 'BSIM', repeat('9', 64), repeat('8', 64), repeat('a', 64),
        1, '\x18', integrity_system_id
    ) RETURNING integrity_id INTO second_integrity_id;

    rejected := false;
    BEGIN
        INSERT INTO mmr_checkpoint (
            last_integrity_id, leaf_count, peaks, commitment, format_version,
            system_uid, system_signature
        ) VALUES (
            second_integrity_id, 1, '[{"height":1}]', repeat('b', 64), 1,
            mmr_system_id, '\x19'
        );
    EXCEPTION
        WHEN check_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'incorrect MMR leaf_count was not rejected';
    END IF;

    INSERT INTO mmr_checkpoint (
        last_integrity_id, leaf_count, peaks, commitment, format_version,
        system_uid, system_signature
    ) VALUES (
        second_integrity_id, 2, '[{"height":1}]', repeat('c', 64), 1,
        mmr_system_id, '\x20'
    ) RETURNING mmr_checkpoint_id INTO checkpoint_id;

    rejected := false;
    BEGIN
        UPDATE mmr_checkpoint SET commitment = repeat('d', 64)
        WHERE mmr_checkpoint_id = checkpoint_id;
    EXCEPTION
        WHEN integrity_constraint_violation THEN
            rejected := true;
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION 'MMR checkpoint mutation was not rejected';
    END IF;

    IF first_integrity_id >= second_integrity_id THEN
        RAISE EXCEPTION 'integrity identity order is inconsistent';
    END IF;
END;
$$;

RESET ROLE;
ROLLBACK;
