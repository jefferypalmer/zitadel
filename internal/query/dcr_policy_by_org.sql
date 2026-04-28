-- T-017 / cavekit-org-dcr-policy.md R3: per-org DCR policy lookup.
--
-- Returns one row containing four columns: the per-org override values
-- (NULL when the org has no override row, or when the org's row stores
-- a NULL field = "inherit"), and the instance-default values (NULL
-- when neither row exists).
--
-- The Go layer (DCRPolicyByOrg) merges these tiers field-by-field:
--   org override → instance default → static-config (`OIDC.DCR.*`)
-- and reports a Scope value per field.
--
-- Cross-instance isolation: the org row's WHERE clause requires
-- instance_id = $1, so a request running under instance A cannot read
-- an override stored under instance B even if the org_id collides.
--
-- owner_removed=TRUE rows are filtered out of the org-tier so a
-- soft-deleted org's override no longer affects the merge (matches the
-- domain_policy precedent).

WITH org_row AS (
    SELECT allowed_audiences,
           registration_access_token_lifetime
      FROM projections.dcr_policies1
     WHERE instance_id = $1
       AND resource_owner = $2
       AND is_default = FALSE
       AND owner_removed = FALSE
     LIMIT 1
), instance_row AS (
    SELECT allowed_audiences,
           registration_access_token_lifetime
      FROM projections.dcr_policies1
     WHERE instance_id = $1
       AND is_default = TRUE
     LIMIT 1
)
SELECT
    (SELECT allowed_audiences                  FROM org_row)      AS org_allowed_audiences,
    (SELECT registration_access_token_lifetime FROM org_row)      AS org_lifetime_ns,
    (SELECT allowed_audiences                  FROM instance_row) AS instance_allowed_audiences,
    (SELECT registration_access_token_lifetime FROM instance_row) AS instance_lifetime_ns;
