-- RELIC migration 004: make one checkpoint extent unambiguous within each
-- MMR format version. Kept separate because migration 002 may already have
-- been installed by an existing deployment.

\set ON_ERROR_STOP on

BEGIN;

SET ROLE relic_owner;
SET search_path = catalogue, public;

ALTER TABLE mmr_checkpoint
    ADD CONSTRAINT mmr_checkpoint_format_version_leaf_count_key
    UNIQUE (format_version, leaf_count);

RESET ROLE;

COMMIT;
