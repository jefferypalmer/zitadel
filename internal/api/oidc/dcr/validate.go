package dcr

// validate.go is the single source of truth for DCR client-metadata
// clamp + validation logic. It is consumed by both the POST /register
// path (cavekit-register-handler.md R2/R4 — T-033/T-034) and the PUT
// /register/{client_id} path (cavekit-manage-handler.md R5 — T-054) so
// the two surfaces enforce identical rules.
//
// This file lands as a skeleton in T-032; the concrete clamp functions
// arrive with T-033/T-034 (request decoding + metadata validate+clamp)
// and are reused unchanged from T-054 (PUT re-clamp). The functions
// listed below are placeholders documenting the intended public API so
// later tasks know the shape to fill.
//
// Intended exports (introduced incrementally by later tasks):
//
//   - ValidateAndClampMetadata(cfg DCRConfig, in *RFC7591Metadata) (*RFC7591Metadata, error)
//       Applies grant_types / response_types / token_endpoint_auth_method /
//       application_type / redirect_uris / subject_type / id_token_alg /
//       request_object_* / software_statement / MaxRedirectURIs /
//       client_name#<lang> rules. Returns a clamped copy plus a
//       zerrors-typed error using `DCR-<5 alphanumeric>` IDs.
//
//   - ApplyDefaultsRFC7591(in *RFC7591Metadata)
//       RFC 7591 §2 + OIDC Reg 1.0 §2 default population (grant_types,
//       response_types, token_endpoint_auth_method, application_type,
//       client_name synthesis).
//
//   - CheckRedirectURIs(cfg DCRConfig, appType string, uris []string) error
//       GetOIDCV1Compliance + AllowedRedirectURIHostPatterns + loopback
//       acceptance for native (cavekit-register-handler.md R4 / T-035).
//
// Until those functions land, validate.go intentionally contains no
// executable code — keeping the file present reserves the import path
// referenced by handler bodies and prevents a downstream task from
// re-litigating the package layout.
