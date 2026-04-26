-- T-020 / cavekit-iat.md R4: IAT lookup by Passwap-encoded token hash,
-- scoped to caller's instance. Used by the registration handler
-- (T-037) to verify a Bearer IAT token: the handler first hashes the
-- presented plaintext (cavekit-iat.md R5) and looks up by hash here.
--
-- The (token_hash) index on the projection covers this WHERE clause.

select row_to_json(r) from (
    select id, instance_id, resource_owner, project_id, token_hash,
           expires_at, max_uses, uses_consumed, consumed_slots,
           allowed_grant_types, allowed_redirect_uri_patterns,
           revoked, created_at, change_date, sequence
    from projections.initial_access_tokens
    where instance_id = $1
      and token_hash = $2
) r;
