-- Backfill the four DCR columns on projections.apps7_oidc_configs that
-- the Phase-1/2 work added to the projection's Init() table definition
-- (internal/query/projection/app.go) but never shipped as a numbered
-- ALTER-TABLE migration. Fresh DBs got the columns via projection
-- Init; upgrading DBs (e.g. v5.0.0-base → v5.0.0-dcr.X) never did, so
-- queries like internal/query/oidc_client_by_id.sql failed at runtime
-- with `ERROR: column c.jwks_inline does not exist (SQLSTATE 42703)`
-- on /oauth/v2/authorize.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS is a no-op on DBs where the
-- projection's Init() already created the columns.
ALTER TABLE IF EXISTS projections.apps7_oidc_configs ADD COLUMN IF NOT EXISTS registration_access_token_hash TEXT;
ALTER TABLE IF EXISTS projections.apps7_oidc_configs ADD COLUMN IF NOT EXISTS registration_access_token_expires_at TIMESTAMPTZ;
ALTER TABLE IF EXISTS projections.apps7_oidc_configs ADD COLUMN IF NOT EXISTS dcr_meta JSONB;
ALTER TABLE IF EXISTS projections.apps7_oidc_configs ADD COLUMN IF NOT EXISTS jwks_inline JSONB;
