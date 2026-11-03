-- RELIC migration 003: separate BSim objects from their Function membership.
-- Existing BSim rows and their associations are preserved.

\set ON_ERROR_STOP on

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

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

INSERT INTO function_bsim (function_id, binary_id, bsim_id, created_at)
SELECT function_id, binary_id, bsim_id, created_at
FROM bsim;

ALTER TABLE bsim
    DROP COLUMN function_id,
    DROP COLUMN binary_id;

COMMENT ON TABLE bsim IS
    'One inspectable BSim object. Function associations are recorded separately so one object may describe multiple Function occurrences.';

CREATE INDEX function_bsim_binary_id_idx ON function_bsim(binary_id);
CREATE INDEX function_bsim_bsim_id_idx ON function_bsim(bsim_id);

CREATE OR REPLACE FUNCTION validate_provenance_target_consistency()
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

GRANT SELECT, INSERT, UPDATE ON function_bsim TO relic_app;

RESET ROLE;

COMMIT;
