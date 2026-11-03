-- RELIC application access policy, version 1.
-- Run as the PostgreSQL superuser after relic-schema-v1.sql.

\set ON_ERROR_STOP on

GRANT CONNECT ON DATABASE relic TO relic_app;

SET ROLE relic_owner;

GRANT USAGE ON SCHEMA catalogue TO relic_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA catalogue TO relic_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA catalogue TO relic_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA catalogue TO relic_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue
    GRANT SELECT, INSERT, UPDATE ON TABLES TO relic_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue
    GRANT USAGE, SELECT ON SEQUENCES TO relic_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue
    GRANT EXECUTE ON FUNCTIONS TO relic_app;

RESET ROLE;

ALTER ROLE relic_app IN DATABASE relic
    SET search_path = catalogue, public;
