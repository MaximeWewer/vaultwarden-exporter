-- Read-only role of vaultwarden-exporter (PostgreSQL). Run it as the owner of
-- the Vaultwarden tables, once Vaultwarden has created them (first start):
--   psql "$OWNER_URL" -v password="'change-me'" -f postgresql-readonly.sql
-- Column-level grants only: never password hashes, keys or vault data.
-- (COUNT(*) needs SELECT on at least one column of the table.)
CREATE ROLE vw_exporter LOGIN PASSWORD :password;
GRANT USAGE ON SCHEMA public TO vw_exporter;
-- metrics
GRANT SELECT (uuid, enabled, verified_at, email, name) ON users TO vw_exporter;
GRANT SELECT (user_uuid, atype, enabled) ON twofactor TO vw_exporter;
GRANT SELECT (user_uuid) ON twofactor_incomplete TO vw_exporter;
GRANT SELECT (uuid, name) ON organizations TO vw_exporter;
GRANT SELECT (uuid, user_uuid, status, atype) ON users_organizations TO vw_exporter;
GRANT SELECT (uuid) ON collections, groups TO vw_exporter;
GRANT SELECT (atype, deleted_at) ON ciphers TO vw_exporter;
GRANT SELECT (file_size) ON attachments TO vw_exporter;
GRANT SELECT (atype) ON sends, devices TO vw_exporter;
GRANT SELECT (status) ON emergency_access TO vw_exporter;
-- events
GRANT SELECT ON event TO vw_exporter;
