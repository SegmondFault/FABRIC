-- FABRIC application access policy, version 1.
-- Run as the PostgreSQL superuser after fabric-schema-v1.sql.

\set ON_ERROR_STOP on

GRANT CONNECT ON DATABASE fabric TO fabric_app;

SET ROLE fabric_owner;

GRANT USAGE ON SCHEMA catalogue TO fabric_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA catalogue TO fabric_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA catalogue TO fabric_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA catalogue TO fabric_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue
    GRANT SELECT, INSERT, UPDATE ON TABLES TO fabric_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue
    GRANT USAGE, SELECT ON SEQUENCES TO fabric_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA catalogue
    GRANT EXECUTE ON FUNCTIONS TO fabric_app;

RESET ROLE;

ALTER ROLE fabric_app IN DATABASE fabric
    SET search_path = catalogue, public;
