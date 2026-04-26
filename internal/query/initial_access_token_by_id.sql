-- T-020 / cavekit-iat.md R4: IAT lookup by ID, scoped to caller's instance.
-- The consume command (T-017) calls this on every retry to re-read
-- {revoked, expires_at, uses_consumed} so revocation/expiry committed
-- between retries is observed.
--
-- Cross-instance and cross-org IATs are filtered at the SQL level by
-- the WHERE clause (instance_id = $1 + resource_owner = $3 when
-- non-empty). Returning sql.ErrNoRows on a miss preserves the
-- not-found semantic the kit specifies.
--
-- Wraps the row in row_to_json so [database.QueryJSONObject] can
-- unmarshal directly into [InitialAccessToken].

select row_to_json(r) from (
    select id, instance_id, resource_owner, project_id, token_hash,
           expires_at, max_uses, uses_consumed, consumed_slots,
           allowed_grant_types, allowed_redirect_uri_patterns,
           revoked, created_at, change_date, sequence
    from projections.initial_access_tokens
    where instance_id = $1
      and id = $2
      and ($3 = '' or resource_owner = $3)
) r;
