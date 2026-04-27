-- T-053 / cavekit-manage-handler.md R4: full DCR app metadata lookup
-- by client_id for the RFC 7592 GET handler.
--
-- Returns every field the GET response body needs that is NOT
-- already on the dispatcher's [ManageContext]:
--   - client_name (from apps7.name)
--   - client_id_issued_at (from apps7.creation_date)
--   - redirect_uris, grant_types[], response_types[],
--     application_type, auth_method_type (from apps7_oidc_configs)
--   - dcr_meta JSONB (the RFC 7591 §2 pass-through fields stamped
--     at registration time per T-041)
--
-- Scoped to caller's instance_id by SQL WHERE — same defence-in-depth
-- as DCRRATLookupByClientID. registration_access_token_hash IS NOT
-- NULL filters out non-DCR apps so the GET handler is opaque to the
-- legacy projects-app surface.
--
-- Wraps in row_to_json so [database.QueryJSONObject] decodes into
-- [DCRGetMetadata] directly.

select row_to_json(r) from (
    select c.app_id,
           a.name as client_name,
           a.creation_date as client_id_issued_at,
           c.redirect_uris,
           c.grant_types,
           c.response_types,
           c.application_type,
           c.auth_method_type,
           c.dcr_meta
    from projections.apps7_oidc_configs c
    join projections.apps7 a on a.id = c.app_id
        and a.instance_id = c.instance_id
        and a.state = 1
    where c.instance_id = $1
      and c.client_id = $2
      and c.registration_access_token_hash is not null
) r;
