---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
complexity: complex
---

# Cavekit: RFC 8707 Resource Indicators

## Scope
Cross-cutting feature: implement RFC 8707 (Resource Indicators) so Claude Code MCP and other RFC 8707 clients can scope tokens by audience. Today Zitadel ACTIVELY REJECTS the `resource` parameter on token exchange and never parses it on `/authorize`. This kit removes the rejection, parses `resource` on both `/authorize` and `/token`, threads it through the auth-request domain object onto `OIDCSession.Audience`, and propagates it into all six token grant handlers so issued access-token `aud` claims reflect the resource. Validates against an `AllowedAudiences` allow-list with empty-list-means-unrestricted sentinel; out-of-list values produce 400 `invalid_target` per RFC 8707 §2.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §1.5, §15.9, §16 "NEW RISK" (sidecar fallback), §17.3 (current state), pass-12 §10 (sidecar definition)
- Spec references: RFC 8707 §2 (`resource` parameter, `invalid_target`)

## Requirements

### R1: Remove existing token-exchange rejection
**Description:** The active rejection of `resource` at token exchange must be removed. Existing test that asserts the rejection must be updated/replaced.

**Acceptance Criteria:**
- [ ] `internal/api/oidc/token_exchange.go:44-46` `oidc.ErrInvalidTarget().WithDescription("resource parameter not supported")` is removed.
- [ ] `internal/api/oidc/token_exchange_test.go:160-167` (existing rejection test) is updated to assert the new acceptance behavior or replaced by the new rfc8707 test coverage.
- [ ] After the change, a token-exchange request with a valid `resource` value succeeds (subject to R3 allow-list).

**Dependencies:** none (this requirement deletes existing behavior).

### R2: Parse `resource` on `/authorize` and `/token`
**Description:** The `resource` query/form parameter must be parsed on both endpoints and carried onto `domain.AuthRequest` via a new field `Resources []string`.

**Acceptance Criteria:**
- [ ] `internal/api/oidc/auth_request_converter.go` reads `resource` from the request (`r.URL.Query()["resource"]` or equivalent) and includes it in the conversion to `domain.AuthRequest` via a new field `Resources []string`.
- [ ] `domain.AuthRequest` (currently `internal/domain/auth_request.go:13` with no `Resources` field) gains a `Resources []string` field.
- [ ] Token endpoint parses `resource` from form values for every grant type listed in R5.
- [ ] If the upstream `github.com/zitadel/oidc/v3` `AuthRequest` struct does NOT expose a `Resource` field at M5 verification time (run: `grep -n "type AuthRequest struct" $(go env GOMODCACHE)/github.com/zitadel/oidc/v3@v3.47.0/pkg/oidc/authorization.go`), the implementation uses the sidecar fallback from R7.

**Dependencies:** R1.

### R3: `AllowedAudiences` allow-list with empty-as-unrestricted sentinel
**Description:** The `OIDC.DCR.AllowedAudiences` config from `cavekit-config.md` R1 acts as an allow-list. Empty list means UNRESTRICTED (any valid URI accepted). Non-empty list rejects values not in the list with `invalid_target`.

**Acceptance Criteria:**
- [ ] When `AllowedAudiences=[]`, any syntactically valid URI in `resource` is accepted.
- [ ] When `AllowedAudiences=["https://api.example.com", "https://mcp.example.com"]`, a request with `resource=https://api.example.com` is accepted.
- [ ] When the same allow-list is configured, a request with `resource=https://other.example.com` is rejected with HTTP 400 and OAuth error code `invalid_target` per RFC 8707 §2.
- [ ] A `resource` value that fails URI syntax validation is rejected with `invalid_target`.
- [ ] Multiple `resource` parameter occurrences are all validated; first invalid → `invalid_target`.

**Dependencies:** R2; `cavekit-config.md` R1.

### R4: Audience computation feeds `aud` claim
**Description:** The parsed resources merge into the audience computed in `internal/api/oidc/auth_request.go createAuthRequestScopeAndAudience()` (~line 84-104) so they flow forward through `domain.AuthRequest.Audience` → `OIDCSession.Audience` → access-token `aud` claim.

**Acceptance Criteria:**
- [ ] `createAuthRequestScopeAndAudience()` accepts the parsed `resource` values and merges them into the audience slice.
- [ ] The merged audience is passed via `auth_request_converter.go:105-121` `CreateAuthRequestToBusiness()` onto `domain.AuthRequest.Audience`.
- [ ] `internal/command/oidc_session.go` `OIDCSession.Audience` carries the merged value through to token issuance (the file currently CARRIES audience but does not COMPUTE it).
- [ ] Issued access tokens contain an `aud` claim equal to (or containing) the requested `resource` value(s) when the request specified them.
- [ ] When no `resource` parameter is supplied, behavior is unchanged from today's scope-derived audience.

**Dependencies:** R2.

### R5: Plumb through every token grant HANDLER
**Description:** All six token grant HANDLERS in `internal/api/oidc/` must propagate `resource` into the issued access-token audience. The plan distinguishes "handlers" from `domain.OIDCGrantType` enum values (only 5: AuthorizationCode/Implicit/RefreshToken/DeviceCode/TokenExchange) — `client_credentials` and `jwt_profile` are handler-level flows not represented in the per-app grant list.

**Acceptance Criteria:**
- [ ] `internal/api/oidc/token_code.go` (authorization_code) propagates `resource` into the audience.
- [ ] **Both refresh-token paths** propagate `resource` per RFC 8707 §2.2 (narrow-only): (a) `refreshTokenV1` (legacy v1→v2 upgrade flow at `internal/api/oidc/token_refresh.go::refreshTokenV1`), AND (b) `RefreshToken` (primary v2 flow via `Commands.ExchangeOIDCSessionRefreshAndAccessToken`). Each path MUST call `narrowAudienceByTokenResources(ctx, originalAudience)` before issuing the new access token. Test coverage MUST include both paths so a future implementer cannot silently drop one. (added 2026-04-27 / F-203)
- [ ] `internal/api/oidc/token_client_credentials.go` propagates `resource`.
- [ ] `internal/api/oidc/token_device.go` (device_code) propagates `resource`.
- [ ] `internal/api/oidc/token_exchange.go` propagates `resource` (after R1 removes the rejection).
- [ ] `internal/api/oidc/token_jwt_profile.go` propagates `resource`.
- [ ] An integration test `rfc8707_resource_test.go` exercises each handler and asserts the issued token's `aud` claim reflects the `resource` value.

**Dependencies:** R2, R4.

### R6: `invalid_target` error envelope
**Description:** Out-of-list values produce HTTP 400 with the OAuth error envelope and code `invalid_target` per RFC 8707 §2.

**Acceptance Criteria:**
- [ ] HTTP status is 400.
- [ ] Body is `{"error":"invalid_target","error_description":"..."}`.
- [ ] `Content-Type: application/json;charset=UTF-8`.
- [ ] The error is returned for both `/authorize` and `/token` flows when validation fails.

**Dependencies:** R3.

### R7: Sidecar-map contingency (fallback)
**Description:** If at M5 kickoff the `zitadel/oidc v3` library `AuthRequest` struct lacks a `Resource` field, a sidecar approach is used: a wrapper type embeds the library struct and a context-scoped map stores resources keyed by auth-request ID.

**Acceptance Criteria:**
- [ ] If sidecar path is taken, the DCR package defines `type authRequestWithResource struct { *oidc.AuthRequest; Resource []string }`.
- [ ] The auth-request converter reads `r.URL.Query()["resource"]` directly and stores the slice in a context-scoped map keyed by auth-request ID.
- [ ] Token issuance retrieves the resource slice from the map and applies it per R4 / R5.
- [ ] An upstream PR is opened against `github.com/zitadel/oidc` IMMEDIATELY at M5 kickoff (in parallel with sidecar implementation, not serialized after a fallback attempt) so that a future refactor can drop the sidecar.
- [ ] If the library DOES expose `Resource`, this requirement is satisfied vacuously and the direct-library path from R2 is used.

**Dependencies:** R2.

## Out of Scope
- DCR-handler-level `resource` (DCR registration metadata does not include `resource`; this kit covers `/authorize` and `/token` only).
- Per-org `AllowedAudiences` overrides (Phase 2; instance-level only in Phase 1).
- RFC 8707 §2.2 narrowing semantics on refresh — the kit propagates resource; precise narrow-versus-broaden enforcement beyond "must be present in original auth-request audience set" is M5 implementation concern.
- Audience-restricted introspection (RFC 7662) extensions.

## Cross-References
- See `cavekit-config.md` R1: `AllowedAudiences` config consumed by R3.
- See `cavekit-register-handler.md` (no direct dependency — this kit is orthogonal to DCR registration but shares the AS-metadata advertisement that signals MCP-readiness).
- See `cavekit-discovery-and-as-metadata.md` R2: `/.well-known/oauth-authorization-server` indirectly signals RFC 8707 readiness via the `registration_endpoint` advertisement that drives MCP probing.

## Source Traceability (brownfield)
- `internal/api/oidc/token_exchange.go:44-46` — active rejection: `oidc.ErrInvalidTarget().WithDescription("resource parameter not supported")`. [GAP] must be removed.
- `internal/api/oidc/token_exchange_test.go:160-167` — existing test asserting current rejection behavior. [GAP] must be updated.
- `internal/api/oidc/auth_request_converter.go:105-121` — `CreateAuthRequestToBusiness()` does not currently reference `resource`. [GAP].
- `internal/api/oidc/auth_request.go:84-104` — `createAuthRequestScopeAndAudience()` derives audience from scope, not from resource. [GAP].
- `internal/api/oidc/auth_request.go:150` — audience derived from scope. [VERIFIED] current state.
- `internal/command/oidc_session.go:33-49` — `OIDCSession.Audience` carries audience but does not compute it. [VERIFIED].
- `internal/domain/auth_request.go:13` — no `Resources` field today. [GAP].
- `github.com/zitadel/oidc/v3` `TokenExchangeRequest.Resource` — [VERIFIED] exists; `AuthRequest.Resource` existence — UNVERIFIED, defer to M5 kickoff grep.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
