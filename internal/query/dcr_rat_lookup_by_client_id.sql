-- T-051 / cavekit-manage-handler.md R2: RAT lookup by client_id for the
-- RFC 7592 manage handlers (GET/PUT/DELETE /oidc/v1/register/{client_id}).
--
-- Returns the Passwap-encoded RAT hash + expires_at + (app_id,
-- project_id, resource_owner) so the dcr verification path can:
--   1. Verify the presented Bearer against the stored hash via Passwap.
--   2. Check expiry against expires_at when non-NULL (RAT.Lifetime > 0).
--   3. Push the rehashed event scoped to the right (project, app)
--      aggregate when Passwap's two-return Verify reports an algorithm
--      rotation.
--
-- Scoped to the caller's instance_id ($1) by SQL WHERE so cross-
-- instance RATs structurally cannot leak even if a misconfigured authz
-- interceptor presented an empty instance.
--
-- registration_access_token_hash IS NOT NULL filters out apps that were
-- created via the legacy projects-app surface (no DCR registration) —
-- only DCR-issued apps have a RAT to verify.
--
-- Wraps the row in row_to_json so [database.QueryJSONObject] can
-- unmarshal directly into [DCRRATLookup].

select row_to_json(r) from (
    select c.app_id,
           a.project_id,
           p.resource_owner,
           c.registration_access_token_hash as token_hash,
           c.registration_access_token_expires_at as expires_at
    from projections.apps7_oidc_configs c
    join projections.apps7 a on a.id = c.app_id
        and a.instance_id = c.instance_id
        and a.state = 1
    join projections.projects4 p on p.id = a.project_id
        and p.instance_id = a.instance_id
        and p.state = 1
    where c.instance_id = $1
      and c.client_id = $2
      and c.registration_access_token_hash is not null
) r;
