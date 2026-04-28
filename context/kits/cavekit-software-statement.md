---
created: "2026-04-28T00:00:00Z"
last_edited: "2026-04-28T00:00:00Z"
complexity: unknown
---

# Cavekit: RFC 7591 §2.3 `software_statement` Verification

## Scope
Defines a production-grade verifier for the RFC 7591 §2.3 `software_statement` JWT presented on `POST /oidc/v1/register`. Phase 1 shipped a config stub (`OIDC.DCR.SoftwareStatement.{Enabled,TrustedIssuers}`) and a hard rejection path — every request carrying a `software_statement` while `Enabled=false` returns `unapproved_software_statement` (`cavekit-register-handler.md` R4). Phase 2 turns the stub into a real capability: parse the JWT, look the issuer up against `TrustedIssuers`, fetch the signing JWKS via the existing SSRF-guarded fetcher, verify signature + standard claims, dedupe by `jti` to prevent replay, and override caller-supplied request body fields with JWT-asserted values per RFC 7591 §2.3. The Phase 1 stub config tree is internal-fork only (not in upstream Zitadel), so refining its shape is internal evolution rather than a public breaking change.

## Source
- Phase 2 design (Approach A) — user-approved.
- Phase 1 carve-outs: `cavekit-config.md` Out of Scope (`software_statement` trusted-issuer verification — Phase 2; config stub only in Phase 1); `cavekit-register-handler.md` Out of Scope (same).
- Brownfield reference: `internal/api/oidc/dcr/jwks_fetcher.go` (`cavekit-security-hardening.md` R2) reused for trusted-issuer JWKS retrieval.
- Spec references: RFC 7591 §2.3 (software_statement), RFC 7517 (JWK), RFC 7519 (JWT), RFC 7515 (JWS).

## Requirements

### R1: Refine `TrustedIssuers` config shape
**Description:** Replace the Phase 1 stub `TrustedIssuers []string` with a typed list of issuer descriptors. Each descriptor names the canonical issuer string, optionally pins a JWKS URI override, and optionally enumerates required claims. An empty `TrustedIssuers` list preserves Phase 1 behavior: every `software_statement` returns `unapproved_software_statement`.

**Acceptance Criteria:**
- [ ] `cmd/defaults.yaml` `OIDC.DCR.SoftwareStatement.TrustedIssuers` is a list of objects with fields `Issuer` (string, REQUIRED), `JWKSURI` (string, OPTIONAL), and `RequiredClaims` (list of strings, OPTIONAL).
- [ ] `Issuer` MUST be a non-empty absolute `https://` URI; startup refuses non-`https` values (loopback override per `OIDC.DCR.JwksURI.AllowLoopbackInDev` permits `http://localhost` for dev only — production MUST be `https`).
- [ ] When `JWKSURI` is empty, the verifier auto-discovers it via OIDC discovery against `${Issuer}/.well-known/openid-configuration` and uses the `jwks_uri` field of that document.
- [ ] When `JWKSURI` is non-empty, it overrides discovery and MUST itself be an absolute `https://` URI subject to the same loopback rule.
- [ ] `RequiredClaims` is a list of zero or more JWT body claim names (strings); the verifier enforces presence + non-emptiness per R7.
- [ ] An empty `TrustedIssuers` list (Phase 1 default) makes any `software_statement` request return `unapproved_software_statement` — Phase 1 behavior preserved as a special case.
- [ ] A new top-level config key `OIDC.DCR.SoftwareStatement.JWKSCacheTTL` defaults to `1h` and bounds the per-issuer JWKS cache lifetime referenced by R4.
- [ ] A new top-level config key `OIDC.DCR.SoftwareStatement.AllowedAlgorithms` defaults to `[RS256, ES256, ES384]` and is enforced by R5; a startup refusal occurs if the list contains any of `none`, `HS256`, `HS384`, or `HS512`.

**Dependencies:** `cavekit-config.md` R1.

### R2: Header parse and `iss` extraction
**Description:** Parse the JWT WITHOUT verifying signature first to extract `iss`. Reject malformed input before any network call.

**Acceptance Criteria:**
- [ ] A `software_statement` value that does not consist of three base64url segments separated by `.` returns 400 `invalid_software_statement` with i18n key `Errors.DCR.SoftwareStatement.InvalidStructure`.
- [ ] Base64url-decode failures on any of the three segments produce the same error.
- [ ] A JSON-decode failure on the header or body segment produces the same error.
- [ ] A header without an `alg` claim produces the same error.
- [ ] A body without an `iss` claim produces the same error.
- [ ] The unsignature-verified extraction is bounded — the JWT body MUST decode to an object < 64 KiB, else `invalid_software_statement` (defence-in-depth against pathologically large JWTs amplifying R4 fetch costs).

**Dependencies:** R1.

### R3: Trusted-issuer lookup
**Description:** The extracted `iss` is compared against the configured `TrustedIssuers` list. Lookup is case-sensitive exact-string match — issuer URIs are RFC 3986 case-sensitive in their authority and path components.

**Acceptance Criteria:**
- [ ] A `software_statement` whose `iss` does not match any configured `TrustedIssuers[].Issuer` exactly returns 400 `unapproved_software_statement` with i18n key `Errors.DCR.SoftwareStatement.UntrustedIssuer`.
- [ ] The error response uses the RFC 7591 §3.2.2 error envelope (`{"error":"unapproved_software_statement","error_description":"..."}`).
- [ ] The `error_description` MUST NOT echo the offending `iss` value (it is attacker-controlled input; reflecting it amplifies a log-injection / phishing surface).
- [ ] An exact match returns the matching `TrustedIssuer` descriptor (Issuer, JWKSURI, RequiredClaims) for use by R4 / R5 / R7.

**Dependencies:** R2.

### R4: JWKS fetch with SSRF guard and per-issuer cache
**Description:** Reuses the SSRF-guarded fetcher from `cavekit-security-hardening.md` R2 to retrieve the trusted issuer's JWKS. Honors an explicit `JWKSURI` override or auto-discovers via OIDC discovery. A per-issuer cache (TTL from `JWKSCacheTTL`) bounds re-fetch frequency.

**Acceptance Criteria:**
- [ ] The verifier calls `internal/api/oidc/dcr/jwks_fetcher.go` for both the discovery document fetch (when no `JWKSURI` override) and the JWKS fetch — same SSRF rules: IP-range deny-list, DNS-rebind protection, redirect cap, response-size cap, total HTTP timeout, all per `cavekit-security-hardening.md` R2.
- [ ] The per-issuer JWKS cache is keyed by `iss` (NOT by URL — protects against URL-rewriting attacks across different issuer descriptors).
- [ ] Cache TTL is `OIDC.DCR.SoftwareStatement.JWKSCacheTTL` (default 1h); a cache miss triggers a refetch.
- [ ] A refetch failure (network error, oversized body, blocked IP) returns 400 `invalid_software_statement` with i18n key `Errors.DCR.SoftwareStatement.JWKSFetchFailed`.
- [ ] When the cache contains a previous successful response and a refetch fails, the verifier MUST NOT serve stale JWKS — fetch failure on key rotation is a security-relevant event, not a "best effort" condition.
- [ ] The fetcher emits the `zitadel.dcr.software_statement_jwks_cache_hits_total{iss,outcome}` counter from R11 with `outcome` ∈ `hit | miss | refetch_failed`.

**Dependencies:** R3; `cavekit-security-hardening.md` R2.

### R5: Signature and claim verification
**Description:** Verify the JWT signature against the JWK whose `kid` matches the JWT header `kid`. Restrict signing algorithms via the `AllowedAlgorithms` config from R1. Enforce standard JWT claims `exp`, `iat`, `jti`, and (if present) `nbf` with bounded clock skew. Replay protection via per-`(iss, jti)` dedupe.

**Acceptance Criteria:**
- [ ] The signing key is selected by exact-string match on JWT header `kid` against `keys[].kid` of the cached JWKS; mismatch returns `Errors.DCR.SoftwareStatement.InvalidSignature`.
- [ ] The JWT header `alg` MUST be a member of `OIDC.DCR.SoftwareStatement.AllowedAlgorithms`; rejection key is `Errors.DCR.SoftwareStatement.UnsupportedAlgorithm`.
- [ ] `none` / `HS*` algorithms are NEVER accepted regardless of `AllowedAlgorithms` content (defence-in-depth — startup refusal in R1 should make this unreachable, but the runtime check is non-optional).
- [ ] `exp` is REQUIRED; missing `exp` returns `Errors.DCR.SoftwareStatement.InvalidStructure`.
- [ ] `exp ≥ now` (no clock skew tolerance on the upper bound — a JWT past expiry is invalid); rejection key is `Errors.DCR.SoftwareStatement.Expired`.
- [ ] `iat` is REQUIRED; `iat ≤ now + 5m` clock skew tolerance; rejection key is `Errors.DCR.SoftwareStatement.InvalidStructure` (issued-in-the-future is structural, not "expired").
- [ ] `nbf`, if present, MUST be `≤ now`; otherwise rejection key is `Errors.DCR.SoftwareStatement.NotYetValid`.
- [ ] `jti` is REQUIRED; absence returns `Errors.DCR.SoftwareStatement.InvalidStructure`.
- [ ] A `(iss, jti)` pair seen previously within the dedupe retention window of R9 returns `Errors.DCR.SoftwareStatement.Replay` with HTTP 400 `invalid_software_statement`.

**Dependencies:** R3, R4, R9.

### R6: Claim-to-metadata override mapping
**Description:** Per RFC 7591 §2.3, JWT-body claims OVERRIDE caller-supplied request body fields for the documented metadata fields. Mapping is explicit and exhaustive; unmapped claims are ignored.

**Acceptance Criteria:**
- [ ] The verifier returns a `MergedMetadata` struct that the register handler uses in place of the caller's request body for the following fields when present in the JWT body: `redirect_uris`, `grant_types`, `response_types`, `scope`, `client_name`, `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`, `software_id`, `software_version`.
- [ ] Other JWT-body claims (e.g., `iss`, `iat`, `exp`, `jti`, `nbf`, custom claims) are NOT mapped onto `MergedMetadata` — they remain part of the verified envelope only.
- [ ] When a mapped claim is present in the JWT body but absent in the request body, the JWT value is used.
- [ ] When a mapped claim is present in BOTH the JWT body and the request body, the JWT value supersedes the request value (RFC 7591 §2.3 explicit precedence).
- [ ] When a mapped claim is absent in the JWT body, the request-body value (if any) is used unchanged; otherwise the standard RFC 7591 default applies (`cavekit-register-handler.md` R2).
- [ ] The mapping is documented in a single code comment that enumerates every mapped claim by name; the unit-test suite asserts the comment and the mapping table agree.
- [ ] After R6 merging, the merged metadata still flows through every clamp from `cavekit-register-handler.md` R4 — the JWT cannot bypass clamps (e.g., a JWT-asserted `redirect_uris=["javascript:alert(1)"]` is still rejected by the scheme allow-list).

**Dependencies:** R5; `cavekit-register-handler.md` R2, R4.

### R7: `RequiredClaims` enforcement
**Description:** Per-issuer `RequiredClaims` are enforced after R5 succeeds. Each named claim MUST be present in the JWT body AND non-empty (an empty string, empty array, empty object, or `null` is treated as absent).

**Acceptance Criteria:**
- [ ] A claim listed in the trusted issuer's `RequiredClaims` that is absent from the JWT body returns 400 `invalid_software_statement` with i18n key `Errors.DCR.SoftwareStatement.MissingRequiredClaim`.
- [ ] A claim listed in `RequiredClaims` that decodes to `null`, `""`, `[]`, or `{}` is treated as absent.
- [ ] A claim listed in `RequiredClaims` that is present and non-empty (string, array, or object) passes the check.
- [ ] The `error_description` names the missing claim by name (the claim name itself is operator-supplied configuration, NOT attacker-controlled — safe to reflect, unlike R3).
- [ ] When `RequiredClaims` is empty / unset, only the standard JWT claims of R5 are enforced.

**Dependencies:** R5.

### R8: Audit JTI population
**Description:** A successfully verified `software_statement` populates the audit field already wired in `cavekit-register-handler.md` R6 (`ApplicationDynamicallyRegisteredEvent.SoftwareStatementJTI`). Replay attempts within the dedupe window are rejected by R5 / R9 before audit emission.

**Acceptance Criteria:**
- [ ] On a successful registration that included a verified `software_statement`, the emitted `ApplicationDynamicallyRegisteredEvent.SoftwareStatementJTI` field equals the verified JWT's `jti` claim.
- [ ] On a registration that did NOT include a `software_statement`, `SoftwareStatementJTI` is the empty string (Phase 1 sentinel preserved).
- [ ] On a registration where the `software_statement` was rejected (any of R2, R3, R5, R7), no `ApplicationDynamicallyRegisteredEvent` is emitted at all (registration failed pre-event-push per `cavekit-register-handler.md` R6).
- [ ] On a replay-rejected registration, the rejection is logged via R11's metric path; no event is emitted.

**Dependencies:** R5, R9; `cavekit-register-handler.md` R6.

### R9: JTI replay-dedupe storage
**Description:** Replay protection requires durable per-`(iss, jti)` storage with retention bounded by JWT max lifetime plus a configurable buffer. **Backing store: Postgres** — reuses Zitadel's existing infrastructure (no new operational dependency), and matches the prevailing pattern for unique-constraint-backed dedupe (e.g., the IAT slot dedupe in `cavekit-iat.md` R3). The write load is bounded — one row per accepted software_statement, with periodic TTL eviction.

**Acceptance Criteria:**
- [ ] A new Postgres table (name follows the prevailing projection-table convention; e.g., `projections.dcr_software_statement_jtis1`) records `(software_statement_iss, software_statement_jti, created_at, expires_at, instance_id)` rows.
- [ ] The unique-constraint enforcement is structural — a Postgres unique index on `(instance_id, software_statement_iss, software_statement_jti)` causes a duplicate INSERT to fail with the standard unique-violation error code (NOT a `SELECT then INSERT` race).
- [ ] Retention is `software_statement.exp + RetentionBuffer` where `RetentionBuffer` is a new config knob `OIDC.DCR.SoftwareStatement.JTIRetentionBuffer` defaulting to `24h`. `expires_at` is stored as the absolute timestamp.
- [ ] A periodic janitor (reusing Zitadel's existing eviction infrastructure — see how IAT exhausted-slot rows are reaped in `cavekit-iat.md`) removes rows past `expires_at`; the dedupe window is therefore bounded to roughly (JWT max lifetime) + RetentionBuffer.
- [ ] A second registration request with the same `(iss, jti)` within the retention window returns 400 `invalid_software_statement` with i18n key `Errors.DCR.SoftwareStatement.Replay` per R5.
- [ ] When the database is unreachable, the verifier MUST fail-closed — a registration carrying any `software_statement` is rejected with `Errors.DCR.SoftwareStatement.InvalidSignature` (an attacker who can knock the dedupe store offline MUST NOT win replay capability).

**Dependencies:** R5.

### R10: i18n keys for all 22 locales
**Description:** Every error key introduced by this kit is translated for every locale shipped under `internal/api/ui/login/static/i18n/`.

**Acceptance Criteria:**
- [ ] Keys `Errors.DCR.SoftwareStatement.InvalidStructure`, `UntrustedIssuer`, `Expired`, `NotYetValid`, `InvalidSignature`, `Replay`, `MissingRequiredClaim`, `UnsupportedAlgorithm`, and `JWKSFetchFailed` are present in all 22 yaml locale files.
- [ ] `internal/i18n/dcr_keys_test.go` is extended; absence in any locale fails the test.
- [ ] Each locale's value is a non-empty, non-raw-key string and reflects locale-appropriate phrasing (no machine-passthrough copies).
- [ ] Fallback behavior from `cavekit-console-ui-docs-and-observability.md` R3 is preserved: missing key falls through to a rendered English string, never the raw key.

**Dependencies:** R2, R3, R5, R7.

### R11: OpenTelemetry surface
**Description:** Verification operations are observable as a span with `iss` / `jti` / `result` attributes and as two counters tracking verification outcomes and JWKS cache behavior.

**Acceptance Criteria:**
- [ ] A new span `oidc.dcr.software_statement.verify` is emitted around the verifier entry point; it is parented by the `oidc.dcr.register` span from `cavekit-console-ui-docs-and-observability.md` R7.
- [ ] Span attributes include `iss` (string, the JWT issuer), `jti` (string, the JWT id; NOT a secret — RFC 7519 §4.1.7 explicitly notes `jti` is identifier-only), and `result` ∈ `accepted | untrusted | expired | replay | invalid_signature | invalid_structure | fetch_failed | unsupported_algorithm | missing_required_claim | not_yet_valid`.
- [ ] Span attributes NEVER include the raw `software_statement` JWT, `nbf` / `exp` timestamps, or the JWKS payload.
- [ ] Counter `zitadel.dcr.software_statement_verifications_total{iss,result}` is incremented on every verifier exit (success and failure).
- [ ] Counter `zitadel.dcr.software_statement_jwks_cache_hits_total{iss,outcome}` is incremented on every JWKS cache lookup with `outcome` per R4.

**Dependencies:** R5; `cavekit-console-ui-docs-and-observability.md` R7, R8.

## Out of Scope
- Per-org `TrustedIssuers` (instance-only in Phase 2; org-level overrides not requested).
- Issuance of `software_statement` JWTs by Zitadel itself (Zitadel is verifier here, not issuer).
- JWE-encrypted software statements (RFC 7591 §2.3 specifies JWS only).
- `software_statement` rotation / revocation lists from trusted issuers.
- Trusted-issuer JWKS pinning by thumbprint (current design pins by `iss` + cached JWKS only).
- Translation tickets for additional locales beyond the 22 yaml bundles.

## Cross-References
- See `cavekit-config.md` R1: the Phase 1 `OIDC.DCR.SoftwareStatement.*` config tree refined by R1.
- See `cavekit-register-handler.md` R2, R4, R6: request decode, clamp surface, and audit-event emission consume R6's `MergedMetadata` and R8's `SoftwareStatementJTI`.
- See `cavekit-security-hardening.md` R2: SSRF-guarded fetcher reused by R4.
- See `cavekit-security-hardening.md` R3: log redaction must cover the `software_statement` field on audit-log emission.
- See `cavekit-console-ui-docs-and-observability.md` R3, R7, R8: i18n fallback contract, OTel span / metric registration.
- See `cavekit-console-phase2.md` R7: full 22-locale rollout for these error keys.

## Changelog
- 2026-04-28: Initial Phase 2 draft.
