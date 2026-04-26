-- T-023 / cavekit-iat.md R6 list: returns IAT metadata rows for the
-- caller's instance, optionally narrowed by project. Wraps each row
-- in row_to_json so the caller can decode an array via QueryJSONObject
-- with a single result column (json_agg). Token plaintext is never
-- in the projection so this query is structurally safe to expose to
-- admin gRPC.

select coalesce(json_agg(row_to_json(r)), '[]'::json) from (
    select id, instance_id, resource_owner, project_id, token_hash,
           expires_at, max_uses, uses_consumed, consumed_slots,
           allowed_grant_types, allowed_redirect_uri_patterns,
           revoked, created_at, change_date, sequence
    from projections.initial_access_tokens
    where instance_id = $1
      and ($2 = '' or project_id = $2)
    order by created_at desc
) r;
