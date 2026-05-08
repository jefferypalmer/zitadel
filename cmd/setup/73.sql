-- Add the apps7_oidc_configs.last_seen_at column on upgrading databases.
-- Fresh databases get the column from the projection's Init() declaration
-- (internal/query/projection/app.go); upgrading databases never run Init,
-- so without this migration the DCR client janitor's reap query
-- (cavekit-dcr-bootstrap-validation.md R12) would fail on `column
-- last_seen_at does not exist`.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS is a no-op when the column already
-- exists from Init() (fresh DBs) or a prior re-run of this step.
ALTER TABLE IF EXISTS projections.apps7_oidc_configs ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
