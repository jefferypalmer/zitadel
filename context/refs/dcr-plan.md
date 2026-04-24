# Plan: OAuth 2.0 Dynamic Client Registration (RFC 7591/7592) for Zitadel

## Context

Zitadel currently exposes OIDC/OAuth client creation only via authenticated gRPC APIs. No standards-compliant self-service endpoint exists that lets a client register itself over HTTP/JSON.

**Primary driver: Claude Code / MCP ecosystem.** The Model Context Protocol 2025-06-18 revision mandates OAuth 2.0 with Dynamic Client Registration for remote MCP servers. Claude Code (and Claude Desktop, `claude.ai` connectors, `mcp-remote`, MCP Inspector, VS Code Copilot MCP, Cursor) all invoke `POST {registration_endpoint}` anonymously on first contact with a DCR-advertising authorization server. Without DCR, Zitadel-protected MCP servers cannot scale: admins would have to pre-register an OAuth app per user per MCP server per laptop.

**Secondary driver:** RFC 7591 / 7592 / OIDC Registration 1.0 conformance — a long-requested feature independent of MCP.

Goal: ship DCR with a default posture that **works out-of-the-box for Claude Code**, while still giving security-sensitive tenants the option to lock it down with Initial Access Tokens.

Non-goals: CIBA, FAPI-DCR profile, SCIM-based provisioning, per-org DCR policy overrides, inline `jwks` (vs `jwks_uri`), `software_statement` verification, `client_name#<lang>` localized names. Phase 1 DOES include a minimal console UI (see §15.2).

---

## 1. Spec Surface (what we must conform to)

### 1.1 RFC 7591 — Dynamic Client Registration
`POST {registration_endpoint}` with `application/json`. Success: 201, JSON echoing metadata plus `client_id`, optional `client_secret`, `client_id_issued_at`, `client_secret_expires_at`, `registration_access_token`, `registration_client_uri`. Errors: 400 with `{"error": "<code>", "error_description": "..."}`. Codes: `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement`. Optional `Authorization: Bearer <initial_access_token>`.

### 1.2 RFC 7592 — Registration Management
`GET/PUT/DELETE {registration_client_uri}` with `Authorization: Bearer <registration_access_token>`. Unknown client or wrong RAT → 401 (NOT 404, per §2.1 — prevents enumeration). DELETE returns 204.

### 1.3 OIDC Registration 1.0
Same endpoint; extra metadata keys; advertise `registration_endpoint` in OIDC discovery.

### 1.4 RFC 8414 — OAuth 2.0 Authorization Server Metadata
MCP clients (including Claude Code) probe `/.well-known/oauth-authorization-server` on the AS host. Required fields per RFC 8414 §2: `issuer`, `authorization_endpoint`, `token_endpoint` (conditional), `response_types_supported`. Advertise additionally (recommended for DCR/MCP): `registration_endpoint`, `code_challenge_methods_supported: ["S256"]`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `scopes_supported`, `jwks_uri`. Handler shares the same struct assembly as the OIDC discovery handler — both documents agree on endpoint values.

### 1.5 RFC 8707 — Resource Indicators
Claude Code sends `resource=<canonical-mcp-url>` on both `/authorize` and `/token`. **Current state confirmed by M0 research**: Zitadel actively REJECTS the parameter on token exchange (`internal/api/oidc/token_exchange.go:44-46` returns `invalid_target` "resource parameter not supported"); `/authorize` never parses it; access-token `aud` is derived from scope (`internal/api/oidc/auth_request.go:150`), not from `resource`. This PR implements full RFC 8707 handling:
- Remove the existing rejection in `token_exchange.go`.
- Add `resource` parsing to the auth-request converter (`auth_request_converter.go`) and carry it onto `domain.AuthRequest` (new field `Resources []string`).
- Plumb through every token grant HANDLER in `internal/api/oidc/` (not OIDCGrantType enum values — pass-9 §5 distinction): `token_code.go` (authorization_code), refresh-token handler, `token_client_credentials.go`, `token_device.go` (device_code), `token_exchange.go`, `token_jwt_profile.go`. Zitadel's `domain.OIDCGrantType` enum only has 5 values (AuthorizationCode/Implicit/RefreshToken/DeviceCode/TokenExchange); client_credentials and jwt_profile are handler-level flows not represented in the per-app grant list.
- Set access-token `aud` claim to the resource value(s). Audience assignment location (pass-12 §2): audience is computed in `internal/api/oidc/auth_request.go` around `createAuthRequestScopeAndAudience()` (line ~84-104) and passed via `CreateAuthRequestToBusiness()` in `auth_request_converter.go:105-121` onto `domain.AuthRequest.Audience`. `internal/command/oidc_session.go:33-49` carries audience on the OIDCSession struct but does NOT compute it. Plumb the RFC 8707 `resource` into `createAuthRequestScopeAndAudience()` — merge into the audience slice that flows forward to `OIDCSession.Audience` and onto token issuance in `token_code.go`.
- Validate against per-client audience allow-list (`AllowedAudiences` in DCR config; default = any valid URI for dynamically-registered clients); out-of-list → 400 `invalid_target` per RFC 8707 §2.
- Scope: roughly 3-4 engineer-days, not 2. ONE open verification: whether `zitadel/oidc v3 AuthRequest` struct has a `Resource` field (known that `TokenExchangeRequest` does). Deferred to M5 start — see §16 "New risk" + §17.3.

### 1.6 RFC 9700 — OAuth 2.0 Security Best Current Practice
PKCE S256 mandatory, no implicit flow for public clients, exact redirect-URI matching, loopback IP ranges special-cased per RFC 8252 §7.3, no plaintext client secrets in logs.

---

## 2. Architecture Decisions

### 2.1 Endpoint path
`POST /oidc/v1/register`, `GET|PUT|DELETE /oidc/v1/register/{client_id}`. Matches OIDC Reg 1.0 convention; colocated with `/oidc/v1/userinfo` and `/oidc/v1/end_session`; already in the existing public-path prefix list (`cmd/start/start.go` oidcPrefixes).

### 2.2 HTTP handler, not gRPC
RFC 7591 is pure JSON/HTTP with exact error-body shapes that do not map cleanly to grpc-gateway. Package `internal/api/oidc/dcr/` — subpackage under `oidc/` (precedent: `internal/api/oidc/sign/`). Mount via `apis.RegisterHandlerPrefixes(...)` alongside `oidcServer`.

### 2.3 Authentication model — REVISED FOR CLAUDE CODE
**Primary mode: anonymous registration, hardened.** Default config enables `POST /register` without any Authorization header. Claude Code, MCP Inspector, `mcp-remote`, and every real-world DCR-compatible OAuth tenant (Cloudflare Workers, WorkOS, Stytch) use this model.

Hardening is applied *in place of* authentication:
- Per-instance rate limit (inherits `limitingAccessInterceptor`).
- Mandatory clamp of `redirect_uris` to the existing OIDC compliance rules + optional host-pattern allow-list.
- Mandatory PKCE S256 when `token_endpoint_auth_method: none`.
- Max request body bytes (`MaxRequestBodyBytes`).
- Forced defaults: `application_type: native` + `token_endpoint_auth_method: none` creates a PUBLIC client (no secret issued) — the exact shape Claude Code needs.
- Every registration is an event; instance admin can query via audit log.
- Instance-level allow-lists of `redirect_uri` host patterns and allowed grant/response/auth-method sets. (Per-org overrides deferred to Phase 2 per §15.6.)

**Secondary mode: Initial Access Token (IAT) required.** Opt-in via `OIDC.DCR.RequireInitialAccessToken: true`. For enterprise tenants that want zero anonymous registration, an admin mints an IAT via new admin gRPC, hands it to a provisioning system, and the provisioning system includes it on the DCR call. Claude Code **cannot** supply an IAT today, so this mode is incompatible with Claude Code by design — tenants choosing it accept that trade-off.

**Registration Access Token (RAT)** — issued on every successful registration for RFC 7592 management. Hashed via Passwap, rotated on every PUT (stricter than RFC's MAY).

Rationale: the threat of "random internet users creating clients" is dramatically lower than the threat of "our flagship IDP integration with Claude Code / MCP breaks on default settings." The plan's earlier "IAT-required default" was wrong for the primary user of this feature. Keep IAT as an opt-in feature for tenants with different threat models.

### 2.4 Resource hierarchy placement
Dynamic clients are standard `Application`s in a `Project` in an `Org`. Reuse the `project.application` aggregate.

**Default placement (anonymous mode):** `DCR.DefaultProjectID` + `DCR.DefaultOrgID` under the instance's default org. Admins can also create a dedicated "DCR Sandbox" project and point the config at it.

**Per-org override:** Instance-level config is the default; an Org can opt-in to its own DCR settings via a future per-org DCR policy aggregate (Phase 2 — not in this plan).

### 2.5 Event model
Reuse existing events where possible. Event-type string convention in `internal/repository/project/` is `project.application.*` (dotted, lowercase) per `applicationEventTypePrefix = projectEventTypePrefix + "application."`. Go type names are `ApplicationXEvent` (CamelCase). Plan lists Go types; wire strings below:
- `project.ApplicationAddedEvent` / type string `project.application.added` (existing) — emitted unchanged for DCR-created apps.
- `project.OIDCConfigAddedEvent` / `project.application.config.oidc.added` (existing) — same.
- `project.ApplicationDynamicallyRegisteredEvent` / type string `project.application.dynamically.registered` (NEW, additive) — carries `{initial_access_token_id, software_statement_jti, registration_method, client_name_unclamped, remote_addr_sha256, user_agent}` for audit. Remote-IP source: `http.RemoteIPStringFromRequest` (`internal/api/http/header.go:107`) — reads `X-Forwarded-For` first hop; falls back to `r.RemoteAddr`; does NOT parse `CF-Connecting-IP`, `X-Real-IP`, or RFC 7239 `Forwarded`. SECURITY.md documents this trust boundary. SHA-256 hashed at write. Purely additive event; existing consumers ignore it.
- `project.ApplicationRegistrationAccessTokenSetEvent` / `project.application.registration_access_token.set` (NEW) — hashed RAT.
- `project.ApplicationRegistrationAccessTokenRotatedEvent` / `project.application.registration_access_token.rotated` (NEW) — on PUT.
- **IAT events scoped to `project` aggregate** (senior-review §3). Go type + wire-string pairs (pass-9 §7):
  - `project.InitialAccessTokenAddedEvent` / `project.initial_access_token.added`
  - `project.InitialAccessTokenConsumedEvent` / `project.initial_access_token.consumed`
  - `project.InitialAccessTokenRevokedEvent` / `project.initial_access_token.revoked`
  
  Rationale: IATs are project-scoped (they mint clients into a specific project); piggy-backing on the project aggregate follows Zitadel convention and avoids inventing a new top-level aggregate. No separate aggregate type. Factory functions: `NewInitialAccessTokenAddedEvent`, `NewInitialAccessTokenConsumedEvent`, `NewInitialAccessTokenRevokedEvent` (matches `NewOIDCConfigAddedEvent` naming).

### 2.6 Client secret behavior
- `token_endpoint_auth_method: none` → no secret issued; response omits `client_secret`. `redirect_uris` MUST be loopback or custom-scheme for native; PKCE enforced.
- `token_endpoint_auth_method: client_secret_basic|client_secret_post` → generate + hash + return once. Reuse `newHashedSecretWithDefault` (internal/command/crypto.go).
- `token_endpoint_auth_method: private_key_jwt` → `jwks_uri` required (inline `jwks` deferred to Phase 2); no secret.
- `token_endpoint_auth_method: client_secret_jwt` → **rejected with `invalid_client_metadata`** in Phase 1 by policy (excluded from `DCR.AllowedAuthMethods` default). Whether `domain.OIDCAuthMethodType` enum supports it: verify at M1. If absent, Phase 2 would add both the enum and allow-list entry.

### 2.7 Defaults-and-clamps
Server has an allow-list. Client *requests* metadata; server *clamps* and MUST echo back clamped values (RFC 7591 §3.2.1). Rule: **if any clamp produces an empty intersection and the field is required, fail with `invalid_client_metadata`.**

- `grant_types` ∩ `DCR.AllowedGrantTypes`.
- `response_types` ∩ `DCR.AllowedResponseTypes`.
- `token_endpoint_auth_method` ∩ `DCR.AllowedAuthMethods`.
- `application_type` ∩ `DCR.AllowedApplicationTypes`.
- `redirect_uris` through `domain.GetOIDCV1Compliance` (actual location `internal/domain/application_oidc.go:221`, senior-review §4) + `DCR.AllowedRedirectURIHostPatterns` regex.
- Unknown fields silently dropped (RFC 7591 §2).

### 2.8 Loopback redirect URIs (Claude Code compatibility) — VERIFIED
**M0 research result: PASSES at registration.** `onlyLocalhostIsHttp` at `internal/domain/application_oidc.go:382-419` accepts `http://localhost:<port>/callback`, `http://127.0.0.1:<port>/callback`, and `http://[::1]:<port>/callback` with arbitrary port numbers (uses `netip.ParseAddr().IsLoopback()` which covers IPv4 127.0.0.0/8 and IPv6 ::1). No code change needed at registration time.

**Token-exchange redirect_uri comparison is exact-string** at `internal/api/oidc/token_code.go:70, 130`. This is OAuth 2.1 §4.1.2.1 compliant for general clients (simple string comparison per RFC 3986 §6.2.1). However, OAuth 2.1 §4.1.2.2 / RFC 8252 §7.3 states the AS **SHOULD** permit any port at request-time for loopback redirect URIs — Zitadel's current behavior is non-ideal here (SHOULD, not MUST). For Claude Code specifically this is a non-issue: Claude Code binds a random port ONCE per session and re-uses it, so the URI is string-identical across registration, authorize, and token exchange. Document this as a known limitation for other loopback clients that re-bind between calls; fix deferred to a future PR (not blocking Claude Code / MCP).

**Test gap identified**: `internal/domain/application_oidc_test.go` has no `[::1]` IPv6 loopback case. M1 adds it as part of `dcr_loopback_redirect_test.go` coverage (plus the existing domain-package unit test file).

---

## 3. Metadata Field Mapping

| RFC 7591 / OIDC field | Zitadel field | Phase 1 behavior |
|---|---|---|
| `client_name` | `AppName` | Stored. `client_name#<lang>` ignored. |
| `redirect_uris` | `RedirectUris` | Required; compliance-checked; loopback-HTTP allowed for native. |
| `grant_types` | `GrantTypes` | Clamp to allow-list. Default: `["authorization_code","refresh_token"]`. |
| `response_types` | `ResponseTypes` | Clamp. Default: `["code"]`. |
| `token_endpoint_auth_method` | `AuthMethodType` | `none`/`client_secret_basic`/`client_secret_post`/`private_key_jwt` accepted; `client_secret_jwt` rejected. |
| `scope` | Clamped against project's allowed scopes | Stored on DCR meta (informational). Token issuance still uses project scope rules. |
| `application_type` | `ApplicationType` | `web`→Web, `native`→Native, `browser`/`user_agent`→UserAgent. |
| `contacts`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri` | DCR meta JSON | Stored, not acted on in Phase 1. |
| `jwks_uri` | Key subsystem | Supported for `private_key_jwt`. SSRF-guarded (§8 T8). |
| `jwks` inline | — | Phase 2. |
| `subject_type` | — | Only `public` accepted; `pairwise` → `invalid_client_metadata`. |
| `id_token_signed_response_alg` | — | Must appear in the server's advertised `id_token_signing_alg_values_supported` (currently `RS256` only; verify at M1 whether other algs are exposed); reject with `invalid_client_metadata` otherwise. |
| `request_object_signing_alg`, `*_encryption_alg` | — | Rejected. |
| `default_max_age`, `require_auth_time`, `default_acr_values`, `initiate_login_uri` | DCR meta | Stored. |
| `post_logout_redirect_uris` | `PostLogoutRedirectUris` | Direct. |
| `backchannel_logout_uri`, `backchannel_logout_session_required` | `BackChannelLogoutURI` | Direct. |
| `software_id`, `software_version` | DCR meta | Stored. |
| `software_statement` | — | Feature flag off by default. If present while disabled → `unapproved_software_statement` 400 (NOT silently dropped — makes future rollout observable in logs). See §8 T6. |

---

## 4. Concrete File-Level Plan

### 4.1 New files

```
internal/api/oidc/dcr/
  handler.go              # POST/GET/PUT/DELETE multiplexer + mux.Router
  register.go             # POST /oidc/v1/register
  manage.go               # RFC 7592 operations
  metadata.go             # JSON request/response structs
  validate.go             # Metadata validation + clamps
  auth.go                 # IAT + RAT verification; anonymous passthrough
  errors.go               # RFC 7591 error bodies + DCR- error code prefix
  config.go               # DCR config struct
  jwks_fetcher.go         # SSRF-guarded HTTP client for jwks_uri
  handler_test.go
  register_test.go
  manage_test.go
  validate_test.go
  auth_test.go
  metadata_test.go
  validate_fuzz_test.go

internal/api/oidc/as_metadata/
  handler.go              # RFC 8414 /.well-known/oauth-authorization-server
  handler_test.go         # Senior review verified: `internal/api/oauth/` dir does not exist; colocate under oidc/.

internal/command/
  dynamic_client_registration.go         # RegisterClient, UpdateClientRegistration, RevokeClientRegistration (reuses existing OIDCApplicationWriteModel from project_application_oidc_model.go — no new write model needed; wrappers add RAT/dcr_meta logic around existing primitives)
  dynamic_client_registration_test.go
  initial_access_token.go                # Add/Consume/Revoke
  initial_access_token_model.go          # InitialAccessTokenWriteModel (new aggregate)
  initial_access_token_test.go

internal/query/
  initial_access_token.go
  initial_access_token_by_id.sql         # //go:embed
  initial_access_token_test.go

internal/query/projection/
  initial_access_token.go                # Projection + UniqueConstraint-conflict retry helper (pass-12 §6 — eventstore-level UniqueConstraint, NOT projection-level SELECT FOR UPDATE; pessimistic locking not needed).
  initial_access_token_test.go

internal/repository/project/
  initial_access_token.go                # initial_access_token.* events
  application_dynamic_registration.go    # ApplicationDynamicallyRegisteredEvent + RAT set/rotated events

internal/api/grpc/admin/
  initial_access_token.go                # Admin gRPC: issue/list/revoke IATs
  initial_access_token_test.go

internal/api/oidc/integration_test/
  dcr_register_test.go
  dcr_manage_test.go
  dcr_errors_test.go
  dcr_iat_test.go
  dcr_iat_concurrency_test.go            # race-safe max_uses
  dcr_rate_limit_test.go
  dcr_secret_auth_test.go                # end-to-end: register → /token works
  dcr_discovery_test.go
  dcr_claude_code_compat_test.go         # replays the exact Claude Code POST body
  dcr_as_metadata_test.go                # RFC 8414 well-known
  dcr_loopback_redirect_test.go          # ports, 127.0.0.1, [::1], localhost
  rfc8707_resource_test.go               # RFC 8707 resource param on /authorize + /token
  dcr_ssrf_test.go                       # jwks_uri SSRF guard
  dcr_log_redaction_test.go              # secrets never appear in logs
  dcr_i18n_fallback_test.go              # unknown Accept-Language falls back to English

apps/docs/content/apis/openidoauth/
  dynamic-client-registration.mdx
apps/docs/content/guides/integrate/
  claude-code-mcp.mdx                    # MCP / Claude Code walkthrough

console/src/app/...                 # (M5.5) Console UI (pass-11 §1 path correction — Zitadel routes projects under plural `projects/apps/`, not `project-detail/apps/`)
  pages/projects/apps/dynamic-clients/           # NEW sub-route co-located with existing app-detail/, app-create/. (Alternative: add a <mat-tab-group> tab inside existing Project settings view — no new directory; decision at M5.5 kickoff with console owner.)
  pages/instance-settings/security/iat/          # IAT admin UI — verify exact subdirectory with console owner; may be under existing admin settings tree.
tests/functional-ui/cypress/e2e/dcr/
  iat.cy.ts
  dcr-clients.cy.ts
internal/api/ui/login/static/i18n/*.yaml   # Backend DCR error keys (Errors.DCR.*) used by /oidc/v1/register handler
console/src/assets/i18n/*.json             # Frontend console strings for Dynamic Clients tab + IAT admin UI

docs/adr/
  ADR-XXXX-dynamic-client-registration.md  # create docs/adr/ if absent; mirrors industry ADR convention

cmd/defaults.yaml                        # (edit) add OIDC.DCR + advertise AS metadata
```

### 4.2 Files to edit

| File | Change |
|---|---|
| `cmd/start/start.go` | Mount `dcrHandler` on `/oidc/v1/register{/*}` path (the broader `/oidc/v1` prefix already exists at ~L446; DCR handler is a gorilla `*mux.Router` that multiplexes POST / GET / PUT / DELETE on the exact path prefix `/oidc/v1/register` with a trailing `{client_id}` capture; see §4.3/§4.4). Route precedence: the more specific `/oidc/v1/register` prefix must be registered BEFORE the general `/oidc/v1` mount (pass-12 §3). **Mount `asMetadataHandler` on `/.well-known/oauth-authorization-server` (NEW prefix — MUST be added to the `oidcPrefixes` slice at L446 so it joins the same `apis.RegisterHandlerPrefixes(...)` call. Pass-12 §4 reaffirms this is critical — previous audit already flagged it.** Pass config. |
| `internal/api/oidc/op.go` | Thread `Config.DCR` through. |
| `internal/api/oidc/server.go` `createDiscoveryConfig` | Append `RegistrationEndpoint` when `DCR.Enabled`. `github.com/zitadel/oidc/v3 v3.47.0` (go.mod pin) already exposes the field (§17.1). Populate with absolute URL `{issuer}/oidc/v1/register` when enabled; leave empty when disabled (the `omitempty` tag drops the key — never emits `null`, per Claude Code Zod bug #38102). Both `/.well-known/openid-configuration` (here) AND the new `/.well-known/oauth-authorization-server` (RFC 8414 handler) advertise `registration_endpoint` identically. |
| `internal/domain/application_oidc.go` | Add `OIDCAppFromRFC7591Metadata` helper. (`onlyLocalhostIsHttp` already port-agnostic per §17.2.) Add unit test for `[::1]` loopback. |
| `internal/query/projection/projection.go` | Register new IAT projection. |
| `internal/query/projection/app.go` | **Two changes, both required (senior-review §10):** (1) Extend `apps7_oidc_configs` with nullable columns per §7 DDL. (2) Extend the `EventReducers` slice inside `appProjection.Reducers()` at `app.go:159-228` (senior-review pass 6 §3 clarified: it's a declarative slice of `handler.AggregateReducer{Event: project.ApplicationXType, Reduce: p.reduceX}` entries under `project.AggregateType`, NOT a switch statement). Add entries for `project.ApplicationDynamicallyRegisteredType`, `project.ApplicationRegistrationAccessTokenSetType`, `project.ApplicationRegistrationAccessTokenRotatedType` plus their `reduce*` methods. Without (2), events persist to the eventstore but never land in `apps7_oidc_configs` — queries would see no metadata. |
| `proto/zitadel/admin.proto` (single monolithic file, verified) | Extend `service AdminService` (package `zitadel.admin.v1`, service definition at line 205) with `CreateInitialAccessToken`, `ListInitialAccessTokens`, `RevokeInitialAccessToken` RPCs. Follow `AddSMTPConfig` style (line ~490) for annotations: `google.api.http`, `zitadel.v1.auth_option` (likely `iam.write`/`iam.read`), `openapiv2_operation` with new tag "Initial Access Tokens". |
| `apps/docs/content/apis/openidoauth/endpoints.mdx` | Add DCR subsection + RFC 8414 note. |
| `CHANGELOG.md` | Feature entry with MCP/Claude Code highlight. |
| `SECURITY.md` | Threat model subsection. |
| `.golangci.yaml` | No change expected. |
| `internal/feature/feature.go` | Add `KeyDynamicClientRegistration Key = 17` constant (next available after `KeyEnableRelationalTables = 16`, verified in senior-review pass 6) and `DynamicClientRegistration bool \`json:"dynamic_client_registration,omitempty"\`` field to the `Features` struct (pass-8 §2 — existing Features fields carry `json:` tags with snake_case names; match that convention exactly). Instance-level feature flag — gates runtime activation at a layer orthogonal to the `OIDC.DCR.Enabled` yaml config. Pattern matches existing `LoginV2`, `DebugOIDCParentError`, etc. **Dual-gate precedence (pass-11 §7)**: yaml `Enabled=false` → handler never mounts → 404 (decided at startup, no runtime cost). yaml `Enabled=true` + runtime feature flag OFF → handler mounted but every request returns 403 `feature_disabled` with the RFC 7591 error body shape. Feature-flag cache TTL is whatever Zitadel's existing feature-flag service uses (eventual consistency; flip propagates within cache window). Both gates must be on for DCR to respond 2xx. M0 sanity check: grep for other in-flight feature-flag PRs claiming Key=17; if collision, bump to 18. |

### 4.3 Handler flow (`register.go`)

```
POST /oidc/v1/register
  1. Content-Type must be application/json (else 415 unsupported_media_type). Body <= MaxRequestBodyBytes (else 413 payload_too_large).
  2. Decode RegistrationRequest; on error → 400 invalid_client_metadata.
     - Apply RFC 7591 §2 defaults + OIDC Registration 1.0 §2 defaults for omitted fields (pass-11 §6 — `application_type` is OIDC-only, not RFC 7591): grant_types → ["authorization_code"] (RFC 7591), response_types → ["code"] (RFC 7591), token_endpoint_auth_method → "client_secret_basic" (RFC 7591), application_type → "web" (OIDC Reg 1.0).
     - Empty client_name → synthesize "Dynamically Registered Client <clientID[:8]>".
  3. Extract Authorization. Route:
     a. If IAT mode and no header → 401 invalid_token.
     b. If header present → authVerifyIAT(ctx, token). On fail → 401.
        Returns {instance_id, org_id, project_id, iat_claims}.
        Consumes one use via race-safe consume (§5).
     c. If anonymous mode and no header → {instance_id from host}, {org_id, project_id from DCR config}. iatID="" (sentinel for anonymous).
  4. Validate + clamp metadata (validate.go).
     - Empty intersection on any required field → 400 invalid_client_metadata with specific field name.
     - software_statement present while SoftwareStatement.Enabled=false → 400 unapproved_software_statement. Extract JTI first for audit.
  5. Build domain.OIDCApp + DCR-meta JSON.
  6. commands.RegisterClient(ctx, app, orgID, projectID, iatID, dcrMeta) returns (clientID, clientSecret?, rat, ratExpiresAt).
     - Emits: ApplicationAddedEvent, OIDCConfigAddedEvent, ApplicationDynamicallyRegisteredEvent, ApplicationRegistrationAccessTokenSetEvent.
  7. Respond 201 Created with:
     - `Content-Type: application/json;charset=UTF-8` (RFC 7591 §3.2.1 mandated).
     - `Cache-Control: no-store`, `Pragma: no-cache`.
     - Body echoing clamped metadata + client_id + client_secret (if any) + client_id_issued_at (unix seconds) + client_secret_expires_at (0 when no expiry per RFC 7591 §3.2.1) + registration_access_token (plaintext, one-time) + registration_client_uri.
     - `registration_client_uri` construction (senior-review pass 7 §1): `issuer := op.IssuerFromContext(ctx)` (same function used in `internal/api/oidc/server.go:176` for OIDC discovery) then `fmt.Sprintf("%s/oidc/v1/register/%s", issuer, clientID)`. MUST use `op.IssuerFromContext` (not `authz.GetInstance(ctx).RequestedDomain()` directly) so multi-instance deployments get the correct issuer per request. Both OIDC discovery and the RFC 8414 metadata handler use the same source.
  8. All 4xx error bodies use `Content-Type: application/json;charset=UTF-8` with RFC 7591 §3.2.2 shape: `{"error":"<code>","error_description":"<text>"}`.
  9. Emit OTel span oidc.dcr.register with IDs-only attrs. Log structured. Metric counter.

Status-code summary:
| Code | When |
|---|---|
| 201 | Successful registration |
| 400 | invalid_client_metadata / invalid_redirect_uri / invalid_software_statement / unapproved_software_statement (RFC 7591 §3.2.2 defined codes) |
| 401 | invalid_token (IAT mode without header or bad IAT) + WWW-Authenticate: Bearer (extension beyond RFC 7591 §3.2.2; standard HTTP auth per RFC 7235) |
| 413 | Body exceeds MaxRequestBodyBytes (extension — defensive, standard HTTP) |
| 415 | Content-Type not application/json (extension — defensive, standard HTTP) |
| 429 | Instance quota exceeded (extension — inherited from access-interceptor, standard HTTP) |
| 404 | DCR disabled at config time — endpoint not mounted (startup chose not to register the handler). Process startup refuses to boot with a validation error if Enabled=true with required config missing. |

Note (per senior-review pass 6 §6): RFC 7591 §3.2.2 only explicitly defines 400 + four error-code strings. The additional 401/413/415/429 codes are implementation-defined extensions permitted by the RFC (not violations) — they exist for defensive security (auth failure, oversized payload, wrong content-type, rate-limit). Documented in the DCR MDX page.

TLS: `/oidc/v1/register` inherits Zitadel's overall TLS posture — same hostname/port/TLS config as `/oidc/v1/userinfo`. RFC 7591 §5 requires TLS in production; document in deployment guide that operators MUST terminate TLS in front of Zitadel (or use Zitadel's built-in TLS) before enabling DCR in production.
```

### 4.4 Handler flow (`manage.go`, RFC 7592)
Per RFC 7592:
- **Authentication**: `Authorization: Bearer <RAT>` required on all operations. Verification: `updatedHash, err := s.hasher.Verify(hashFromApps7OIDCConfigs.registration_access_token_hash, bearerPlaintext)` — reuses Passwap exactly like client_secret verification at `internal/api/oidc/client.go:250-257`. RAT expiry (if `RegistrationAccessToken.Lifetime > 0`) checked against `registration_access_token_expires_at` column (see §7). **Hash-rotation handling (pass-9 §3)**: if `updatedHash != ""`, the passwap algorithm has rotated and this RAT's stored hash must be updated. Emit `project.application.registration_access_token.rehashed` event to persist the new hash (silent rotation — not exposed to the client; RAT value unchanged). If hash-rotation on read is deemed out-of-scope for Phase 1, document as known limitation: "RAT hash algorithm rotation only applies on the next PUT, not on GET verification." Decision at M4 implementation time; default to silent rotation (matches existing client-secret behavior).
- **401 on missing/wrong RAT AND unknown client_id** (anti-enumeration per RFC 7592 §2.1). Body: `{"error":"invalid_token","error_description":"..."}` + `WWW-Authenticate: Bearer error="invalid_token"`.
- **GET**: 200 + current metadata — includes `client_id`, `client_id_issued_at`, `client_secret_expires_at`, `redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`, `application_type`, `client_name`, and any DCR-meta fields previously stored. Omits `client_secret` (unretrievable plaintext) and `registration_access_token` (one-time issue) per RFC 7592 §2 MAY-omit allowance. `registration_client_uri` re-emitted identically to the POST response.
- **PUT**: full replacement. MUST re-run every clamp in §2.7 (grant_types, response_types, auth_method, application_type, redirect_uris, audiences). Rejects disallowed changes with 400 invalid_client_metadata. Auth-method transitions: `none`→`client_secret_*` issues a new client_secret; `client_secret_*`→`none` clears it; →`private_key_jwt` requires a valid `jwks_uri` in the new body (rejected with `invalid_client_metadata` otherwise); any→`client_secret_jwt` rejected (§2.6). Rotates RAT on every successful PUT; old RAT immediately invalid. Returns 200 with new RAT in body.
  - Idempotency caveat: a retried PUT after a successful first call will fail 401 (old RAT invalid). Client must handle per RFC 7592 — document in API docs.
- **DELETE**: 204 No Content. Calls `command.RemoveApplication` (`internal/command/project_application.go:121`) which emits `ApplicationRemovedEvent`. **Senior-review confirmed: `RemoveApplication` does NOT currently revoke issued tokens.** RFC 7592 §4 requires token invalidation on deletion. Implementation in M4 MUST add a sibling command `RevokeApplicationTokens(ctx, projectID, appID)` that emits revocation events for every outstanding access/refresh/refresh-access token for that client_id before calling `RemoveApplication`. Alternative (fallback if revocation-event infrastructure is complex): document as known limitation in CHANGELOG + SECURITY.md and require operators to separately trigger token revocation via existing endpoints. Decision to be made in M4 after surveying token-revocation command primitives.

### 4.5 gRPC IAT admin API

Extend `proto/zitadel/admin.proto`, service `zitadel.admin.v1.AdminService` (line 205). Do NOT create a new file — Zitadel convention is a single monolithic admin proto.

```proto
rpc CreateInitialAccessToken(CreateInitialAccessTokenRequest) returns (CreateInitialAccessTokenResponse);
rpc ListInitialAccessTokens(ListInitialAccessTokensRequest) returns (ListInitialAccessTokensResponse);
rpc RevokeInitialAccessToken(RevokeInitialAccessTokenRequest) returns (RevokeInitialAccessTokenResponse);

message CreateInitialAccessTokenRequest {
  string project_id = 1;
  google.protobuf.Duration lifetime = 2;
  int32 max_uses = 3;                                  // 0 = unlimited
  repeated string allowed_grant_types = 4;
  repeated string allowed_redirect_uri_patterns = 5;
  string description = 6;
}
```

IAT value: 48-byte random base64url, prefixed `zdiat_` (Zitadel Dynamic-registration Initial Access Token — the prefix makes IATs grep-recognizable in logs/tickets). Verify at M1 what prefix Zitadel's existing PATs use; pick a new distinct prefix if collision. Hashed with Passwap at rest. Only the hash is persisted; plaintext returned once at issue time.

---

## 5. Race-Safe IAT `max_uses` (CRITICAL DESIGN)

Research confirmed Zitadel's eventstore does **not** provide atomic counter semantics. A naive "load WriteModel → check uses < max → push event" sequence has a race window that allows double-spend under concurrent registrations.

### Chosen approach: **UniqueConstraint per use-slot with bounded retry**
Each IAT reserves N pre-numbered "use slots" at creation time. Each consumption emits an `initial_access_token.consumed` event with a `UniqueConstraint` on `(iat_id, use_index)`. The DB-level unique constraint (at eventstore transaction commit) guarantees exactly one consumer wins per slot.

**Retry on race loss:** A consumer that loses the DB-level unique-constraint race re-reads the projection, picks the next unreserved slot, and retries — up to **3 retries** total. After the 3rd `ThrowAlreadyExists`, return `401 invalid_token` with `error_description: "initial access token exhausted"`. This gives legitimate callers graceful degradation under short bursts without opening an unbounded retry loop that could exhaust request-handling goroutines.

```
// On IAT creation (max_uses = N, or "unlimited" sentinel):
NewInitialAccessTokenAddedEvent(ctx, agg, id, hash, maxUses=N, expiresAt)
  -> no unique constraints (IAT id uniqueness handled by aggregate ID)

// On consumption attempt (pass-9 §6 clarification):
// Re-fetch the projection EVERY retry — not just the first try —
// so a revoke/expiry committed between retries is observed.
iat := query.InitialAccessTokenByID(ctx, id)
if iat.Revoked || time.Now().After(iat.ExpiresAt) {
    return ErrInitialAccessTokenInvalid
}
useIndex := nextUnreservedSlot(ctx, iat)   // from same projection read
NewInitialAccessTokenConsumedEvent(ctx, agg, useIndex)
  UniqueConstraints: [NewAddEventUniqueConstraint(
    "iat_uses",
    iatID + ":" + strconv.Itoa(useIndex),
    "Errors.DCR.IAT.SlotAlreadyConsumed")]
```

- For `max_uses: 0` (unlimited): emit `initial_access_token.consumed` events with a monotonically increasing `use_index` from the projection, WITHOUT a UniqueConstraint (a duplicate index collision is benign since usage is unbounded). Events still written — essential for audit.
- For `max_uses: N`: reserve slot numbers `[1..N]`. Projection tracks consumed set. If projection reports all N consumed → fail pre-push with 401 invalid_token. If a race causes two requests to target the same slot, the unique constraint rejects the second at DB commit.
- Eventstore transaction wraps unique-constraint check + event insert, so rollback is atomic.
- On conflict the caller receives `zerrors.ThrowAlreadyExists`; handler retries up to 3 times (re-reading projection between retries). After 3rd failure, translate to `401 invalid_token` with `error_description: "initial access token exhausted"`.

### Concurrency tests
`dcr_iat_concurrency_test.go` — three scenarios:
- **Exhaustion path**: create IAT with `max_uses=3`, fire 10 concurrent DCR requests; assert exactly 3 succeed, 7 receive `401 invalid_token` with `error_description: "initial access token exhausted"`.
- **Retry-success within budget**: create IAT with `max_uses=4`, fire 4 concurrent DCR requests with a test hook forcing each to initially pick slot 1; assert all 4 succeed via the 3-retry fallback (slot 1→fail→slot 2, etc. — 3 retries covers slots 2/3/4).
- **Retry-budget boundary**: `max_uses=5`, 5 concurrent forced-collision → 4 succeed, 1 receives `401 invalid_token: initial access token exhausted` (retry budget exhausted before reaching slot 5).

### Projection
`initial_access_tokens` table:
```
id TEXT PK,
instance_id TEXT NOT NULL,
resource_owner TEXT NOT NULL,
project_id TEXT NOT NULL,
token_hash TEXT NOT NULL,
expires_at TIMESTAMPTZ NULL,
max_uses INT NOT NULL,          -- 0 = unlimited
uses_consumed INT NOT NULL DEFAULT 0,
consumed_slots INT[] NOT NULL DEFAULT '{}',
allowed_grant_types TEXT[] NULL,
allowed_redirect_uri_patterns TEXT[] NULL,
revoked BOOL NOT NULL DEFAULT FALSE,
created_at TIMESTAMPTZ NOT NULL,
change_date TIMESTAMPTZ NOT NULL,
sequence BIGINT NOT NULL
```
Indices: `(instance_id, project_id)`, `(token_hash)`.

Separate eventstore unique-constraints table (already exists) holds `iat_uses:iatID:slotIndex` rows.

### Concurrency characteristic (pass-7 §4 note)
Because IAT events are on the `project` aggregate (§2.5), concurrent IAT consumptions on the SAME project are serialized by Zitadel's per-aggregate sequence lock — not just by per-slot unique-constraints. For a single-project DCR deployment (the common `DefaultProjectID` setup), this bounds concurrent-registration throughput to the project's eventstore write rate. Two independent-project consumptions parallelize normally. Operators needing higher per-instance DCR throughput should partition into multiple DCR projects. Handler godoc MUST call this out: "Concurrent consumption of IATs from the same project is serialized by eventstore aggregate locking; use multiple projects for parallelism."

---

## 6. Configuration (cmd/defaults.yaml)

**Decision (user-confirmed):** `Enabled: false` default. Operators opt-in per-instance. Upgrade-safe. Claude Code / MCP works "one flag away."

```yaml
OIDC:
  # ... existing ...
  DCR:
    Enabled: false                       # Opt-in. Set true + DefaultProjectID + DefaultOrgID to activate.
    RequireInitialAccessToken: false     # Anonymous by default when enabled (Claude Code has no IAT support).
    DefaultProjectID: ""                 # REQUIRED when Enabled=true && RequireInitialAccessToken=false; startup aborts with non-zero exit if missing.
    DefaultOrgID: ""                     # REQUIRED when Enabled=true && RequireInitialAccessToken=false; same startup-abort on missing.
    MaxRedirectURIs: 10
    MaxRequestBodyBytes: 65536
    AllowedGrantTypes:                   # client_credentials EXCLUDED by default (admin opt-in).
      - authorization_code
      - refresh_token
    AllowedResponseTypes:
      - code
    AllowedAuthMethods:
      - none                             # REQUIRED for Claude Code.
      - client_secret_basic
      - client_secret_post
      - private_key_jwt
    AllowedApplicationTypes:
      - native                           # Claude Code sets native.
      - web
    AllowedRedirectURIHostPatterns: []
    AllowedAudiences: []                 # RFC 8707 resource indicators. Sentinel (pass-11 §3): EMPTY = unrestricted (any valid URI accepted). Populate with explicit values to restrict. Inverted from Go convention ("empty=deny") — operators read "[] means no restrictions" per the comment. Code gate: `if len(cfg.AllowedAudiences) == 0 { return allow } for _, a := range cfg.AllowedAudiences { if a == reqResource { return allow } } return invalid_target`.
                                         # Example to restrict: AllowedAudiences: ["https://api.example.com", "https://mcp.example.com"]
    # CORS: Reuse existing Zitadel CORS middleware (`internal/api/http/middleware/cors_interceptor.go`).
    # No DCR-specific CORS config — the global middleware wraps public endpoints uniformly.
    # Per-endpoint override (if needed for MCP Inspector) goes through the shared middleware's opts, not here.
    RegistrationAccessToken:
      Enabled: true
      Lifetime: 0s                       # Go time.Duration; 0s = no expiry (RFC 7592 §3 MAY).
    InitialAccessToken:
      DefaultLifetime: 24h
      DefaultMaxUses: 1
    SoftwareStatement:                   # Feature-flagged stub. If software_statement sent while Enabled=false,
      Enabled: false                     # respond with `unapproved_software_statement` (not silently ignored).
      TrustedIssuers: []                 # Phase 2 wires verification.
    ClientSecretExpiresIn: 0s            # Go time.Duration; 0 = no expiry (RFC 7591 `client_secret_expires_at: 0`).
    JwksURI:
      HTTPTimeout: 10s
      AllowLoopbackInDev: false          # Dev override; production MUST leave false. When true, removes 127.0.0.0/8 and ::1/128 from DisallowedIPRanges.
      DisallowedIPRanges:                # SSRF defense for jwks_uri (applied in prod)
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
        - "169.254.0.0/16"               # link-local incl. cloud metadata
        - "::1/128"
        - "fc00::/7"
        - "fe80::/10"
```

**Upgrade note:** `DCR.Enabled=false` by default (§15.1), so existing installs unaffected on upgrade. When an operator flips `Enabled=true` AND `RequireInitialAccessToken=false` with empty `DefaultProjectID`/`DefaultOrgID`, the Zitadel process FAILS TO START with a clear error message (non-zero exit, no HTTP 503 — the handler never gets a chance to serve). CHANGELOG documents this requirement.

**Rollback / disable behavior (pass-8 §6):** If an operator enables DCR, clients register, then flips `Enabled=false`:
- The `/oidc/v1/register` endpoint stops being mounted (handler unregistered). New registration requests → 404.
- Existing DCR-created apps in `apps7_oidc_configs` remain fully functional for normal OIDC flows (authorize/token/userinfo). They are standard apps with extra audit metadata; disabling DCR does not orphan them.
- RFC 7592 GET/PUT/DELETE on `/oidc/v1/register/{client_id}` also stops being mounted. Existing RATs become unusable for self-service management; admins can still delete the app via the management API.
- Projection columns (`dcr_meta`, `registration_access_token_hash`, etc.) stay populated; no rollback DDL needed. If DCR is re-enabled later, existing data is intact.
- Active IATs become unusable (no handler to consume them); admin can revoke via gRPC even while DCR is disabled (gRPC path is gated by the feature flag separately).
- Schema migrations are additive (nullable columns) — no rollback DDL. Operators CAN drop the columns if they want but it's not required.

---

## 7. Database Migrations / Projections

1. `apps7_oidc_configs` ALTER — nullable columns. Full DDL (per senior-review pass 6 §5):
```sql
ALTER TABLE apps7_oidc_configs
  ADD COLUMN dcr_meta JSONB NULL,
  ADD COLUMN registration_access_token_hash TEXT NULL,
  ADD COLUMN registration_access_token_expires_at TIMESTAMPTZ NULL,
  ADD COLUMN initial_access_token_id TEXT NULL;

CREATE INDEX idx_apps7_oidc_configs_rat_hash
  ON apps7_oidc_configs(registration_access_token_hash)
  WHERE registration_access_token_hash IS NOT NULL;
```
  - `dcr_meta` — JSONB for RFC 7591 metadata extras (logo_uri, policy_uri, contacts, software_id, software_version, default_max_age, default_acr_values, etc.).
  - `registration_access_token_hash` — Passwap-encoded hash; null when RAT disabled.
  - `registration_access_token_expires_at` — null = no expiry.
  - `initial_access_token_id` — audit link; null in anonymous mode.
  - Partial index on RAT hash for RFC 7592 GET/PUT/DELETE lookup (skip null rows — most rows have no RAT).
2. New `initial_access_tokens` table (§5).
3. No changes to eventstore tables; uses existing unique-constraints machinery.

Number migrations in `internal/query/projection/projection.go` registration order. Coordinate numbering with any PRs in flight (M1 checklist).

---

## 8. Security Review & Threat Model

| # | Threat | Mitigation |
|---|---|---|
| T1 | Unauthenticated spam → eventstore/storage DoS | Inherit instance access quota; `MaxRequestBodyBytes`; emit only if compliance passes; tenants needing stricter: flip `RequireInitialAccessToken=true`. |
| T2 | Attacker registers attacker-controlled `redirect_uri` and phishes via subsequent auth flow | Clients isolated per Project; consent screen (existing); optional `AllowedRedirectURIHostPatterns` allow-list; audit log contains source IP + UA. **Accepted residual risk in anonymous mode** — documented in SECURITY.md and mitigated per-tenant by IAT mode. |
| T3 | Public client downgrade | PKCE S256 enforced when `token_endpoint_auth_method: none`. |
| T4 | RAT leakage → silent takeover/delete | One-per-client, long random, hashed at rest, rotate on every PUT, log all 7592 ops as events. |
| T5 | IAT replay | `max_uses` enforced via unique constraint (§5); `expires_at`; admin revoke. |
| T6 | `software_statement` alg confusion | Off by default; when on: pinned JWKS per issuer; reject `alg:none`; no symmetric unless configured. |
| T7 | Enumeration via RFC 7592 | 401 (not 404) for unknown IDs AND wrong RAT; constant-time Passwap compare. |
| T8 | SSRF via `jwks_uri` | HTTP client with: (a) `DisallowedIPRanges` filter (see §6 config); (b) DNS rebind mitigation (resolve once, dial the resolved IP); (c) redirect following capped at 3 hops and re-validated per hop; (d) response size cap 1 MiB; (e) timeout 10s. Located in `internal/api/oidc/dcr/jwks_fetcher.go`. Table-driven unit tests in `jwks_fetcher_test.go` cover RFC1918, link-local, IPv6 ULA, loopback, oversized bodies, redirect traps. |
| T9 | Stored XSS via `client_name`, `logo_uri` | Treated as untrusted display-only; console escapes; no auto-fetch of `logo_uri`. |
| T10 | Over-broad grant types | Server intersects with allow-list. |
| T11 | Cross-tenant / cross-instance escalation | IAT carries `{instance_id, org_id, project_id}`; anonymous mode uses instance-from-host + configured defaults; handler ignores request-level claims trying to move clients. **Tests required** (`dcr_iat_test.go`). |
| T12 | Timing side-channel on IAT/RAT verification | Passwap's `Verify` is constant-time by construction. For `client_id` existence lookups (RFC 7592): always call `passwap.Verify` against a stored hash even on unknown client_id (use a static dummy hash) so the response-time distribution doesn't leak existence. Document the pattern in the handler. |
| T13 | CSRF on `/register` | Endpoint is POST JSON; no session/cookie credentials read. **Reuse existing Zitadel CORS middleware at `internal/api/http/middleware/cors_interceptor.go`** (senior-review §6) rather than invent DCR-specific. DCR endpoint wraps in the same `CORSInterceptor(...)` chain used by other public endpoints. If per-endpoint override is needed for MCP Inspector browser support, extend the existing middleware's `CORSInterceptorOpts` — not a new `DCR.CORS` config tree. Never `*` origin; never `Access-Control-Allow-Credentials: true`. |
| T14 | client_secret cached at proxy/CDN | Response `Cache-Control: no-store, Pragma: no-cache`. |
| T15 | Logs leak client_secret / RAT / IAT | M0 task: inspect HTTP middleware `internal/api/http/middleware/log_interceptor.go` AND gRPC interceptor `internal/api/grpc/server/connect_middleware/log_interceptor.go` (pass-12 §1 — gRPC admin returns plaintext IAT; must cover both paths). If either logs request/response bodies, add a redactor that strips `client_secret`, `registration_access_token`, `software_statement`, `Authorization` header, and IAT plaintext (response-body field `token` on `CreateInitialAccessTokenResponse`). If bodies not logged, add a defensive redaction wrapper specifically in both the DCR HTTP handler and the IAT admin gRPC handler. Tests: `dcr_log_redaction_test.go` (HTTP path, existing) + `dcr_grpc_iat_logging_redaction_test.go` (gRPC path, NEW). Also verify `internal/logstore/` HTTP access-logging path doesn't leak IATs (separate audit-log subsystem). |
| T16 | Registration under rapid IP rotation | Instance quota + per-IP at reverse proxy; doc recommendation. **Accepted residual risk per §15.3 — docs-only mitigation, product-signed-off in ADR. No dedicated test file (pass-10 §2); SECURITY.md explicitly documents the trade-off.** |
| T17 | Discovery `registration_endpoint: null` breaks Claude Code (Zod parse error, GH #38102) | Unit test in `dcr/handler_test.go` covers BOTH discovery endpoints (OIDC discovery + RFC 8414 metadata) with two table cases (pass-10 §7): (a) `DCR.Enabled=false` → key absent from JSON body, (b) `DCR.Enabled=true` → key present with non-null absolute URL. Integration test `dcr_discovery_test.go` covers end-to-end with the mounted handler. |
| T18 | Projection lag between IAT consume push and projection update → wrong slot picked on next request | DB-level UniqueConstraint at eventstore commit is authoritative; projection-based slot picker retries on conflict up to 3×; worst case caller sees 401 under contention. Concurrent registrations within the same project incur eventstore sequence locking (cross-ref §5 "Concurrency characteristic"); projection lag is absorbed by the UniqueConstraint DB check and 3-retry budget. Documented in `initial_access_token.go` handler comment. **New test (pass-11 §4)**: `dcr_iat_projection_lag_test.go` (integration) — artificially delays projection updates via test hook, verifies retry-success rate ≥ 95% under worst-case lag; R2 performance test cross-references. |
| T19 | Eventstore flood under registration burst | Anonymous-mode registration emits 4 events per call (ApplicationAdded + OIDCConfigAdded + ApplicationDynamicallyRegistered + ApplicationRegistrationAccessTokenSet). IAT mode adds a 5th (`initial_access_token.consumed`) + 1 unique-constraint row. Mitigation: instance quota + R2 performance test under burst; tune retry budget if needed. |
| T20 | Claude Code CLI changes request shape | `dcr_claude_code_compat_test.go` locks the payload shape; CI hook re-runs against current Claude Code CLI quarterly (R3 follow-up). |

### Senior-engineer pre-merge checklist
- [ ] Threat model reviewed by security lead; ADR signed.
- [ ] OWASP ASVS L2 auth section walked.
- [ ] OIDF Conformance DCR profile run locally; results attached to PR.
- [ ] Log redaction verified via integration test asserting no secret substrings in captured stderr.
- [ ] SSRF guards verified with local malicious test server (attacker-controlled DNS).
- [ ] Race test (§5) passes via `go test -race -count=1000 -run=TestIATConcurrency ./internal/command/` with zero flakes.

---

## 9. Testing Strategy

### 9.1 Unit (no build tag)
- `dcr/validate_test.go` — table-driven. Fragment in redirect_uri, mixed HTTP/HTTPS, loopback-for-native (127.0.0.1, [::1], localhost, arbitrary ports), custom scheme for native only, empty `redirect_uris` for auth_code, unknown auth method, `client_secret_jwt` rejected, `pairwise` subject rejected, wrong `id_token_signed_response_alg` rejected, `software_statement` present while SoftwareStatement.Enabled=false → unapproved_software_statement (JTI audited), RFC 7591 §2 defaults applied when fields omitted, empty client_name synthesizes a default.
- `dcr/auth_test.go` — IAT missing/malformed/expired/revoked/used-up/cross-project/cross-instance/cross-org.
- `dcr/metadata_test.go` — JSON round-trip, unknown fields dropped, Claude Code exact payload deserializes.
- `dcr/handler_test.go` — status codes, `Cache-Control` headers, `WWW-Authenticate` on 401, body shapes, `registration_endpoint` never null in discovery when enabled, key OMITTED when disabled.
- `dcr/jwks_fetcher_test.go` — SSRF: denies RFC1918, link-local, IPv6 ULA, loopback; enforces size cap, timeout, redirect cap.
- `dcr/validate_fuzz_test.go` — `FuzzParseRegistrationRequest` (JSON decode path) AND `FuzzValidateClientMetadata` (clamp+validate path with randomized structs; asserts no panic and consistent output).
- `command/dynamic_client_registration_test.go` — follows `project_application_oidc_test.go` pattern: `Want` struct, `expectEventstore(expectFilter..., expectPush...)`, `id_mock.NewIDGeneratorExpectIDs`.
- `command/initial_access_token_test.go` — add/consume/revoke/expire + unique-constraint slot reservation.
- `query/initial_access_token_test.go` — SQL mock regex (mirror `app_test.go`).
- `projection/initial_access_token_test.go` — reducer + `testExecuter` INSERT/UPDATE verification.
- `api/oauth/as_metadata/handler_test.go` — RFC 8414 field presence, never-null invariant.

### 9.2 Integration (`//go:build integration`, `internal/api/oidc/integration_test/`)
- `dcr_register_test.go` — web + `client_secret_basic`, native + `none`+PKCE, JWT-asserted + `private_key_jwt`+`jwks_uri`.
- `dcr_claude_code_compat_test.go` — replay the exact JSON body Claude Code sends (from GH #2527): `{client_name, redirect_uris:["http://localhost:54212/callback"], grant_types:["authorization_code","refresh_token"], response_types:["code"], token_endpoint_auth_method:"none", application_type:"native", scope:"openid profile email offline_access"}`. Assert 201, assert no `client_secret`, assert the authorization_code flow completes end-to-end with PKCE.
- `dcr_loopback_redirect_test.go` — every combination of `localhost` / `127.0.0.1` / `[::1]` / different ports accepted.
- `dcr_manage_test.go` — GET returns metadata, PUT mutates + rotates RAT (old RAT fails), DELETE 204 + subsequent GET 401.
- `dcr_errors_test.go` — every RFC 7591 error code with exact body shape.
- `dcr_iat_test.go` — issue, use, max_uses enforce, expiry, revoke; cross-instance + cross-org abuse rejected.
- `dcr_iat_concurrency_test.go` — three scenarios per §5: (1) exhaustion: `max_uses=3`, 10 concurrent → exactly 3 succeed + 7 receive `401 invalid_token`; (2) retry-success within budget: `max_uses=4`, 4 concurrent forced-collision on slot 1 → all 4 succeed via 3 retries; (3) retry-budget boundary: `max_uses=5`, 5 concurrent forced-collision → 4 succeed, 1 fails with `401 invalid_token: initial access token exhausted`.
- `dcr_rate_limit_test.go` — spray > instance quota → 429.
- `dcr_secret_auth_test.go` — registered secret authenticates `/token` via `zitadel/oidc v3` RP client.
- `dcr_discovery_test.go` — `registration_endpoint` in OIDC discovery + RFC 8414 metadata when enabled; omitted when disabled; never null.
- `dcr_as_metadata_test.go` — `/.well-known/oauth-authorization-server` serves correct fields.
- `dcr_ssrf_test.go` — `jwks_uri` pointing at `169.254.169.254` / `127.0.0.1:whatever` / DNS that resolves to private IP → rejected.
- `dcr_log_redaction_test.go` — capture handler logs, assert no `client_secret` / RAT / IAT values appear.
- `rfc8707_resource_test.go` — `resource` parameter on `/authorize` + `/token` accepted; token `aud` claim reflects the value; rejected values outside allow-list return 400 `invalid_target` per RFC 8707 §2.
- `dcr_i18n_fallback_test.go` — with an unsupported `Accept-Language`, error_description falls back to English, never emits a raw translation key (`Errors.DCR.*`).
- `dcr_delete_revokes_tokens_test.go` — register client, issue access+refresh token, DELETE client via RFC 7592, assert old access token fails `/oauth/v2/introspect` and refresh token fails `/oauth/v2/token` (senior-review §5: RFC 7592 §4 compliance).
- `dcr_timing_side_channel_test.go` (pass-8 §3) — T12 mitigation test. Issue RFC 7592 GET against (a) a known-valid client_id with wrong RAT, (b) a nonexistent client_id with any RAT. Measure response time over 1000 iterations each; assert mean/p95 delta within a tight bound (e.g., < 5ms). Verifies the dummy-hash passwap.Verify path executes for unknown client_id.
- `dcr_iat_projection_lag_test.go` (pass-11 §4) — T18 mitigation test. Inject projection-update delay via test hook; fire concurrent IAT consumes; assert ≥95% succeed within 3 retries even with the lag. Cross-references R2 performance test.

### 9.3 E2E / Cypress
Setup chain (pass-12 §8): each DCR Cypress test follows the convention established in existing tests (e.g., `applications.cy.ts`) — log in as instance admin via `cy.login()`, land on Organization view, create a throwaway project (if not using fixture), then execute test. Admin context is required for IAT RPCs (permission `iam.write` from §4.5); instance admin session lives for the test file scope. Cleanup via `cy.cleanupProjects()` or similar existing hook.

- `tests/functional-ui/cypress/e2e/dcr/iat.cy.ts` — admin creates IAT, list shows it, revoke removes it from active list.
- `tests/functional-ui/cypress/e2e/dcr/dcr-clients.cy.ts` — Dynamic Clients tab under a project lists a registered app with its DCR metadata; link to view audit events.

### 9.4 Fuzz (CI gate)
Run both targets on PRs touching `dcr/`:
```
go test -run=^$ -fuzz=FuzzParseRegistrationRequest -fuzztime=60s ./internal/api/oidc/dcr/
go test -run=^$ -fuzz=FuzzValidateClientMetadata   -fuzztime=60s ./internal/api/oidc/dcr/
```
Fail on any new crasher.

### 9.5 Conformance
Run OpenID Foundation Certification DCR profile before first release; attach report.

### 9.6 "Actually ran" gate
All unit + integration + fuzz tests MUST pass locally in the feature branch before opening a PR. CI re-runs them. The branch merges only when CI is green AND the conformance report is attached.

---

## 10. Documentation

### 10.1 New
`apps/docs/content/apis/openidoauth/dynamic-client-registration.mdx`:
- RFC 7591, 7592, 8414, 9700, OIDC Reg 1.0, RFC 8707, RFC 8252 references.
- **"Using with Claude Code / MCP" section** — concrete walkthrough with `claude mcp add --transport http https://...`.
- Endpoint table, metadata table (supported/clamped/ignored/rejected), error table.
- IAT mode and admin-API usage.
- SSRF + rate-limit guarantees.
- Security considerations (mirror SECURITY.md).
- Two curl examples (confidential web, public native).
- Discovery sample + RFC 8414 sample.
- Config reference + upgrade note.

### 10.2 Updates
- `endpoints.mdx` — DCR subsection.
- `authn-methods.mdx` — `none` noted as Phase-1 supported.
- `guides/integrate/` — new `claude-code-mcp.mdx` walkthrough (short; links back).
- `CHANGELOG.md` — feature entry lead with "Works with Claude Code out-of-the-box."
- `SECURITY.md` — threat model subsection with T1-T20.
- ADR — §2 decisions captured.
- Blog post draft (not in this plan's scope but track in Linear).

---

## 11. Audit & Observability

- Events ARE the audit log: every DCR op emits eventstore events with `{instance_id, org_id, project_id, client_id, iat_id, software_statement_jti, remote_addr_sha256, user_agent, registration_method}`.
- OpenTelemetry spans: `oidc.dcr.register`, `oidc.dcr.read`, `oidc.dcr.update`, `oidc.dcr.delete`, `oidc.dcr.iat.consume`. **Attributes contain IDs only, never secret values.**
- Structured logs via `github.com/zitadel/logging` using `logging.WithFields("k", v).WithError(err).Warn(...)` pattern (matches `internal/api/assets/asset.go`).
- Metrics (OTel counter/histogram). Zitadel convention uses dotted names with a `zitadel.` prefix (verified in `backend/v3/instrumentation/metrics/metric.go`; senior-review pass 8 §1). Names:
  - `zitadel.dcr.registrations_total` (counter, labels: `result`, `auth_method`, `application_type`)
  - `zitadel.dcr.request_duration_seconds` (histogram)
  - `zitadel.dcr.errors_total` (counter, label: `code`)
  - `zitadel.dcr.iat.consumed_total` (counter)
  - `zitadel.dcr.iat.exhausted_total` (counter)

---

## 12. Project Style Guide (the DCR Cavekit)

This section codifies Zitadel's conventions so the feature "fits" the codebase. Research-backed; citations inline.

### 12.1 Layout
- Package `internal/api/oidc/dcr` (subpackage — precedent: `internal/api/oidc/sign/`).
- File names `snake_case.go`, one concern per file.
- Unit tests: same package, `_test.go` suffix.
- Integration tests: `internal/api/oidc/integration_test/` with `//go:build integration` tag on line 1.

### 12.2 Error codes
`zerrors.Throw*` with prefix `DCR-<5 alphanumeric>` (e.g., `DCR-Wx2Y9`). Pattern from `internal/query/oidc_client.go:81` (`QUERY-...`), `internal/api/oidc/error.go:44` (`OIDC-...`), `internal/command/action_v2_execution.go:25` (`COMMAND-...`).

Use types: `ThrowInvalidArgument`, `ThrowNotFound`, `ThrowAlreadyExists`, `ThrowPreconditionFailed`, `ThrowUnauthenticated`, `ThrowInternal`.

### 12.3 Logging
```go
logging.WithFields("instanceID", id, "clientID", clientID).WithError(err).Warn("dcr failed")
```
Redact: `client_secret`, `registration_access_token`, `software_statement`, `Authorization`.

### 12.4 Events
Factory `NewXEvent(ctx, agg, ...) *XEvent`, `Payload()`, `UniqueConstraints()`. Pattern from `internal/repository/project/oidc_config.go:20-83`.

### 12.5 Commands + WriteModels
CQRS pair: `AddXCommand()` validation closure + `XWriteModel` struct + `AppendEvents` + `Reduce`. Pattern from `internal/command/project_application_oidc.go` + `_model.go`.

### 12.6 Tests
- Table-driven with `Want` struct.
- `expectEventstore(expectFilter(...), expectPush(...))`.
- `id_mock.NewIDGeneratorExpectIDs(t, "id1", "id2")`.
- SQL assertions via `regexp.QuoteMeta` (`internal/query/app_test.go`).

### 12.7 Queries
`//go:embed X.sql` files next to the `.go`. `database.QueryJSONObject[T]` for row-to-struct. Pattern from `internal/query/oidc_client.go:70-97`.

### 12.8 Projections
`handler.NewHandler(ctx, cfg, new(xProjection))`, `Name()`, `Init()`, `Reducers()`, `reduceXAdded(e)`. Column constants `XColumnYZ = "yz"`. Pattern from `internal/query/projection/app.go`.

### 12.9 HTTP handler
Constructor `NewHandler(deps) http.Handler`. Gorilla mux sub-router; middleware chain wrapper. Pattern from `internal/api/assets/asset.go:32-115`.

### 12.10 Proto
Package `zitadel.admin.v1` for IAT admin API. `option (google.api.http)` for REST mapping. `buf.gen.yaml` pipeline picks it up.

### 12.11 Config YAML
Two-space indent, CapitalCase keys, env var override in comment, viper struct tags.

### 12.12 Imports / formatting
Three groups: stdlib, third-party, `github.com/zitadel/zitadel/internal/*`. Enforced by `gci` via golangci-lint.

### 12.13 Linters to satisfy
`exhaustive` (every enum switch: `domain.OIDCGrantType`, `OIDCResponseType`, `OIDCAuthMethodType`, `OIDCApplicationType`), `gocognit` (keep functions simple), `errorlint` (use `%w`), `bodyclose`, `contextcheck`, `sqlclosecheck`.

### 12.14 Commits / PR
Conventional commits: `feat(oidc): ...`, `fix(dcr): ...`, `docs(dcr): ...`, `test(dcr): ...`. Multi-line body with rationale. Co-Authored-By footer. **PR scope for DCR**: single feature PR covering all DCR subsystems (the whole thing is the feature). Per-commit scope within that PR stays tight — one milestone per commit. This exception to "one subsystem per PR" is justified because DCR is a cross-cutting feature where partial merges would leave the branch in an inconsistent state (e.g., event emitter without projection handler). Documented deviation, not an unnoticed contradiction (pass-8 §5).

### 12.15 License headers / pre-commit
None required. No custom pre-commit hook in the repo.

---

## 13. Single-Branch Execution Plan (main-thread orchestration with background agents)

### 13.1 Shape
One feature branch `feat/oidc-dynamic-client-registration` cut from `main`. The main conversation thread is the **orchestrator** — it does not write code directly. It launches background `Agent` tasks using `run_in_background: true`, each implementing a discrete milestone on that same branch. The orchestrator:

1. Creates the branch + worktree.
2. Dispatches M0 (ADR + config scaffold) in background.
3. Awaits M0 notification. Reviews via `superpowers:code-reviewer` (+ `ck:inspector` if Cavekit is initialized).
4. Dispatches M1 (IAT domain) in background.
5. Awaits notification. Reviews.
6. Loops through M2…M6 identically, with each milestone gated on the previous passing its tests and inspection.
7. After M6, launches code-review, security-review, and conformance-run agents in parallel.
8. Opens PR.

Every worker agent is given: the branch name, the milestone's spec (copy of the relevant section of this plan), the DCR Cavekit (§12), and a hard rule: "Run `go test -race` for all affected packages and `golangci-lint run` before returning. Report test output verbatim."

### 13.2 Milestones (executed sequentially on one branch)

| ID | Agent type | Scope | Exit criteria |
|---|---|---|---|
| M0 | general-purpose | ADR + config schema + `cmd/defaults.yaml` block + feature flag `KeyDynamicClientRegistration = 17` in `internal/feature/feature.go` (both gate layers). Config struct wiring (`op.Config.DCR *dcr.Config` + `internal/api/oidc/dcr/config.go`). Issuer-path startup warning logic. Add `/.well-known/oauth-authorization-server` to the public prefix registration in `cmd/start/start.go`. **Also add `OIDC.DCR.Enabled: true` + `DefaultProjectID`/`DefaultOrgID` pointing at the integration-test fixture IDs** (identified via `internal/integration/oidc.go` / `Instance.DefaultOrganizationID()`) to `internal/integration/config/client.yaml`. M0 **must verify at runtime** that `iam.write` / `iam.read` permission strings (proposed for the new IAT admin RPCs, per §4.5) are valid constants in `internal/api/authz/` — if not, identify and use the actual registered permission strings before the M1 dispatch. Budget: **1.5 days**. Defer fuzz-target scaffolding to M6. | ADR merged; config loads; feature flag present (default off in prod defaults.yaml, on in integration client.yaml); `go build` clean; no behavior change when flag off. **NEW (pass-10 §1): `/.well-known/oauth-authorization-server` registered and reachable — `curl http://localhost:8080/.well-known/oauth-authorization-server` returns 404 when `DCR.Enabled=false` (endpoint unmounted) AND returns 200 with JSON body when `Enabled=true`.** **NEW (pass-10 §3): Integration test fixture IDs correctly resolved — running `go test -run=TestInstance_BasicLoadsConfig -tags integration` passes.** **NEW (pass-10 §4): Permission strings for IAT RPCs verified against authz package.** |
| M1 | general-purpose | IAT domain: command/query/projection/events/gRPC (extend `proto/zitadel/admin.proto` per §17.5), race-safe consume with 3-retry slot picker (§5), unit + concurrency tests (`dcr_iat_concurrency_test.go` — all three scenarios per §5). Adds `[::1]` IPv6 loopback unit test to `application_oidc_test.go` (§17.2 test gap). | All M1 unit + concurrency tests green; `-race` clean for 1000 iterations; `golangci-lint` clean; `buf generate` clean (proto regen produces valid OpenAPI). Integration tests deferred until handler wired in M2. |
| M2 | general-purpose | `POST /oidc/v1/register` happy paths (web, native, JWT). Route wiring. OIDC discovery `registration_endpoint` advertisement (never null). | `dcr_register_test.go` + `dcr_secret_auth_test.go` + `dcr_discovery_test.go` green. |
| M3 | general-purpose | RFC 7591 full error matrix + clamp logic + SSRF-guarded jwks fetcher + log redaction + `software_statement` rejection path (unapproved_software_statement). | `dcr_errors_test.go` + `dcr_ssrf_test.go` + `dcr_log_redaction_test.go` green. |
| M4 | general-purpose | RFC 7592 GET/PUT/DELETE + RAT rotation. **M4 pre-work task (senior-review pass 6 §1):** survey Zitadel's token-revocation primitives — `internal/command/oidc_session.go:266` `RevokeOIDCSessionToken` is per-session only; no bulk `RevokeAllTokensForApp` exists. Decision at M4 start: (a) build new `RevokeApplicationTokens` command (emits revocation events for every active token of that `client_id`) — +1-2 days; OR (b) fallback: document as known limitation in CHANGELOG + SECURITY.md, require operators to call `/oauth/v2/revoke` per token, get product sign-off. Default assumption: (a); if survey reveals revocation-event infrastructure missing for bulk, fall back to (b). | `dcr_manage_test.go` green; new `dcr_delete_revokes_tokens_test.go` asserts access token issued pre-DELETE is rejected on `/oauth/v2/introspect` post-DELETE (path (a)) — OR asserts 204 DELETE + document-limitation note in release notes (path (b)). |
| M5 | general-purpose | RFC 8414 `/.well-known/oauth-authorization-server` endpoint. Claude Code compat test. Loopback redirect tests (including `[::1]`). **RFC 8707 full implementation** (M0-confirmed NOT supported today): remove `token_exchange.go:44-46` rejection, add `resource` parsing to auth-request converter, thread through every token grant handler (authorization_code, refresh_token, client_credentials, device_code, token_exchange, jwt_profile), set `aud` claim from resource, return `invalid_target` for out-of-list. Verify whether `zitadel/oidc v3` `AuthRequest` struct exposes `Resource` field; if not, open upstream PR in parallel + use sidecar map temporarily. | `dcr_as_metadata_test.go` + `dcr_claude_code_compat_test.go` + `dcr_loopback_redirect_test.go` + `rfc8707_resource_test.go` + existing token tests regression-green. |
| M5.5 | general-purpose (frontend) | Console UI: Dynamic Clients read-only tab under Project settings; Initial Access Tokens admin surface under Instance Settings → Security (issue / list / revoke). **Pre-work (pass-11 §1)**: confirm with console owner whether Dynamic Clients is (a) a new sub-route `console/src/app/pages/projects/apps/dynamic-clients/` co-located with `app-detail/`, OR (b) a `<mat-tab-group>` tab inside the existing project-detail view (no new routing). M5.5 uses Angular + NgModule + RouterModule + Material components — match existing patterns. **i18n keys (pass-11 §2)** enumerated upfront (in `console/src/assets/i18n/en.json`; flat keys with dot-separated namespace matching existing Zitadel style like `DESCRIPTIONS.APPS.*`): `DESCRIPTIONS.DCR.CLIENTS.TITLE`, `DESCRIPTIONS.DCR.CLIENTS.EMPTY`, `DESCRIPTIONS.DCR.CLIENTS.REGISTRATION_METHOD`, `DESCRIPTIONS.DCR.CLIENTS.IAT_USED`, `DESCRIPTIONS.DCR.IAT.TITLE`, `DESCRIPTIONS.DCR.IAT.ISSUE_BUTTON`, `DESCRIPTIONS.DCR.IAT.DIALOG_TITLE`, `DESCRIPTIONS.DCR.IAT.LIFETIME_LABEL`, `DESCRIPTIONS.DCR.IAT.MAX_USES_LABEL`, `DESCRIPTIONS.DCR.IAT.REVOKE_BUTTON`, `DESCRIPTIONS.DCR.IAT.REVOKE_CONFIRM`, plus column labels for expires_at, created_at, uses_consumed. English canonical + German maintained (primary locales Zitadel ships with human translation); other 19 locales ship with English fallback keys and translation tickets opened per locale. Cypress smoke tests. | Cypress `dcr/iat.cy.ts` + `dcr/dcr-clients.cy.ts` green; `pnpm nx affected` clean; i18n fallback test green; all listed keys present in `en.json` + `de.json`. |
| M6 | general-purpose | Fuzz tests (`FuzzParseRegistrationRequest` + `FuzzValidateClientMetadata`), docs (mdx page + CHANGELOG + SECURITY + ADR finalization + Claude Code walkthrough + hostname-root requirement note), i18n fallback test. | Docs render; fuzz runs 60s clean; i18n fallback test green. |
| R1 | superpowers:code-reviewer (primary); `ck:inspector` also dispatched only if Cavekit is initialized in the repo | Independent code review and plan-vs-implementation gap audit. | Findings list; zero MUST-FIX blockers (SHOULD-FIX tracked as follow-ups). |
| R2 | general-purpose | Security review against §8 threat table. SSRF live test with attacker DNS. Log redaction live test. Product sign-off on rotating-IP residual risk (captured in ADR). | All T1-T20 verified. |
| R3 | general-purpose | OIDF Conformance suite DCR profile. | Report attached to PR. |

### 13.3 Orchestrator invariants
- Never edits code directly; only dispatches and reviews.
- One milestone in flight at a time (sequential dependency).
- After each milestone, runs `superpowers:code-reviewer` (and `ck:inspector` only if Cavekit is initialized) against the milestone diff BEFORE dispatching the next.
- If inspection finds a MUST-FIX, dispatches a follow-up worker for that milestone before proceeding.
- All work on the single branch; rebased on main periodically.
- Final PR opened by the orchestrator, not a worker.

### 13.4 Worker agent prompt template
Each worker prompt contains: (1) branch name + worktree path, (2) exact spec excerpt from this plan, (3) DCR Cavekit §12, (4) the claim "Run tests before returning — include full `go test -race ./...` output in your report," (5) hard no-scope-creep rule. Workers use `general-purpose` subagent type (primary). `isolation: "worktree"` is set on the FIRST dispatch (M0); subsequent dispatches re-use the path returned in the M0 result. Frontend milestone M5.5 uses `general-purpose` too (no specialized frontend agent needed; the Cavekit §12 + existing Angular/React patterns in `console/` guide it).

### 13.5 Failure handling
If a worker returns failing tests, the orchestrator reviews the output, composes a targeted fix prompt, and re-dispatches. If the same milestone fails 3 times, the orchestrator pauses and asks the user for direction.

### 13.5.1 Rebase-conflict handling (pass-8 §4)
The orchestrator invariant "Never edits code directly" applies to source files. **Merge/rebase conflict resolution is NOT code editing** and is explicitly permitted for the orchestrator. When periodic `git rebase main` produces conflicts:
1. Orchestrator attempts auto-resolution for non-semantic conflicts (whitespace, import order).
2. For semantic conflicts, orchestrator dispatches a focused "resolve rebase conflicts" worker with the conflict markers + the relevant plan section.
3. If conflicts recur across 2+ rebases on the same files, orchestrator escalates to the user.
Workers themselves never rebase — they operate on the branch as-of dispatch.

### 13.5.2 Worker return format (pass-8 §4 addendum)
Every worker must return a structured report:
- `status`: `success` | `partial` | `failure`
- `files_changed`: list of paths.
- `tests_run`: exact commands + stdout.
- `tests_passed`, `tests_failed`: counts.
- `blockers`: free text if `partial`/`failure`.
- `next_step`: recommended follow-up.

### 13.5.3 Milestone exit-criteria verification rubric (pass-10 §6)
Orchestrator applies per-milestone checklist BEFORE marking a milestone accepted. Each milestone's `tests_run` block must show:
- The exact test commands from §14.1 for the packages that milestone touched.
- `-race` flag present in test commands for any package with concurrent logic (M1 mandatory).
- Per-package pass/fail summary extracted from output.
- `golangci-lint run` output clean (zero diagnostics) for changed packages.
- For milestones touching proto (M1) or projection (M2): `buf generate` + `pnpm generate` outputs clean (no uncommitted diff).

If the worker's report is missing any of the above, orchestrator re-dispatches for evidence rather than proceeding.

### 13.6 Why this shape
- Single branch: matches the user's requirement ("done as a branch, all work in a single task in one go").
- Sequential milestones: each depends on previous artifacts; parallel would cause merge conflicts on the same files.
- Background dispatch: main thread doesn't block on compile/test cycles; user can query progress.
- Inspector gates: catches drift between plan and implementation early, when fixes are cheap.

---

## 14. Verification

### 14.1 Commands (run in feature branch)
```bash
# Unit
go test -race ./internal/api/oidc/... \
                ./internal/api/oauth/as_metadata/... \
                ./internal/command/... \
                ./internal/query/... \
                ./internal/query/projection/... \
                ./internal/repository/project/... \
                ./internal/domain/...

# Fuzz (60s smoke, both targets)
go test -run=^$ -fuzz=FuzzParseRegistrationRequest -fuzztime=60s ./internal/api/oidc/dcr/
go test -run=^$ -fuzz=FuzzValidateClientMetadata   -fuzztime=60s ./internal/api/oidc/dcr/

# Integration
go build -cover -race -tags integration -o .artifacts/bin/.../zitadel.test main.go
go test -race -count 1 -tags integration -timeout 60m \
  ./internal/api/oidc/integration_test/...

# Lint
golangci-lint run --timeout 15m --config ./.golangci.yaml

# NX
pnpm nx affected --targets lint test build
```

### 14.2 Must-pass tests (gate for merge)
1. `dcr_claude_code_compat_test.go` — Claude Code's exact payload → 201 → tokens issued.
2. `dcr_iat_concurrency_test.go` — all three scenarios per §5: exhaustion (`max_uses=3`, 10 concurrent), retry-success within budget (`max_uses=4`, 4 collisions), retry-budget boundary (`max_uses=5`, 5 collisions → 4 succeed + 1 exhausted).
3. `dcr_ssrf_test.go` — private IPs blocked on jwks_uri.
4. `dcr_log_redaction_test.go` — no secrets in logs.
5. `dcr_discovery_test.go` — `registration_endpoint` is non-empty string or key absent, never null. Both OIDC discovery and RFC 8414 metadata.
6. `rfc8707_resource_test.go` — `resource` parameter accepted on /authorize + /token; `aud` claim reflects it; out-of-list → `invalid_target`. Critical for Claude Code MCP audience isolation.
7. `dcr_iat_test.go` (pass-11 §5) — IAT lifecycle correctness: issue, consume, `max_uses` enforcement, expiry (expired IAT → 401), revoke (admin-revoked IAT → 401), cross-instance + cross-org abuse rejection. Security-critical for enterprise IAT mode.
8. `dcr_delete_revokes_tokens_test.go` — RFC 7592 §4 compliance: access token issued pre-DELETE is rejected on `/oauth/v2/introspect` post-DELETE. Or (if M4 fallback path taken) the test asserts 204 DELETE + documented limitation in CHANGELOG.

### 14.3 Manual end-to-end (developer smoke)
```bash
# Claude Code path
curl -sS -X POST http://localhost:8080/oidc/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"test","redirect_uris":["http://localhost:54212/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"native","scope":"openid profile email offline_access"}' \
  | tee /tmp/reg.json

# AS metadata
curl -sS http://localhost:8080/.well-known/oauth-authorization-server | jq .registration_endpoint

# RFC 7592 round-trip
RAT=$(jq -r .registration_access_token /tmp/reg.json)
RCU=$(jq -r .registration_client_uri /tmp/reg.json)
curl -sS -H "Authorization: Bearer $RAT" $RCU | jq .
curl -sS -X DELETE -H "Authorization: Bearer $RAT" $RCU -i  # 204

# Real Claude Code
claude mcp add --transport http mymcp https://mcp.example.com
# Should prompt browser auth, succeed, store client_id in ~/.claude.json
```

### 14.4 OIDF Conformance
Run DCR profile; attach `results.html` to PR.

---

## 15. Resolved Decisions (from user audit review)

All prior open questions and senior-audit action items resolved:

1. **`DCR.Enabled` default: `false`.** Opt-in posture. Upgrade-safe. Documented as "one flag away from MCP-ready." Flip to `true` in a later major version once telemetry supports the change. (A4 closed.)
2. **Console UI: minimal UI included in Phase 1.**
   - New "Dynamic Clients" read-only tab under Project settings (lists DCR-registered apps with their audit metadata; no edit here — users manage via RFC 7592 endpoint).
   - Initial Access Tokens admin surface under Instance Settings → Security: issue / list / revoke. Wraps the new gRPC.
   - Adds a frontend milestone M5.5 and a Cypress smoke test (`tests/functional-ui/cypress/e2e/dcr/iat.cy.ts`, `dcr-clients.cy.ts`).
   - Reviewers needed: console frontend owner + i18n translations for new strings across all 21 locales.
   - Translation-ticket ownership (pass-12 §9): English canonical + German maintained in Phase 1. For the other 19 locales, M5.5 worker opens one GitHub issue per locale using the repo's existing translation issue template (or creates a template if none exists), assigned to the `@zitadel/i18n` team or equivalent maintainer group. Link the template in M5.5 exit criteria. Issues track locale-coverage parity as a post-ship follow-up — NOT blocking Phase 1 merge.
3. **Rotating-IP flood: docs-only in Phase 1.** Rely on instance quota + reverse proxy. SECURITY.md documents the residual risk explicitly; product sign-off line in ADR. (T1 mitigation text updated.)
4. **`client_credentials` NOT in default `AllowedGrantTypes`.** Admin opt-in per instance. Documented.
5. **`software_statement`: off, feature-flagged.** Config stub present; when disabled, a submitted `software_statement` is rejected with `unapproved_software_statement` (not silently dropped — makes future enablement observable). Phase 2 wires verification against trusted issuers.
6. **Per-org DCR settings: Phase 2.** Phase 1 = instance-wide `OIDC.DCR` only. A later phase adds an org-level DCR policy aggregate.
7. **Upstream `oidc/v3.DiscoveryConfiguration.RegistrationEndpoint`: RESOLVED — field already exists** in `github.com/zitadel/oidc/v3 v3.47.0` (the `go.mod` pin), at `pkg/oidc/discovery.go` with tag `json:"registration_endpoint,omitempty"`. No upstream PR, no vendor patch. Just assign the field when `DCR.Enabled`. 0.5 engineer-week removed from estimate.
8. **IAT race retry: up to 3 slot retries.** After 3 consecutive `UniqueConstraint` rejections, return 401 `invalid_token` with `error_description: "initial access token exhausted"`. `dcr_iat_concurrency_test.go` asserts all three scenarios per §5: exhaustion, retry-success within budget, and retry-budget boundary.
9. **RFC 8707 `resource`: implemented in this PR. M0 research confirmed current state = NOT_SUPPORTED** (token_exchange.go:44-46 actively rejects with `invalid_target`; `/authorize` never parses; `aud` derived from scope not resource). Scope: remove the rejection, plumb `resource` through auth request + every token grant handler, set `aud` from resource, add `AllowedAudiences` config, return `invalid_target` for out-of-list values. Revised effort: **3-4 engineer-days** (was 2). Tracked as a mini-milestone inside M5.
10. **`.well-known` at hostname root: documented as a deployment requirement.** DCR/MCP support requires Zitadel deployed at a hostname root (no URL subpath). Documented in the new DCR guide, the deployment docs, and the CHANGELOG. Startup does NOT hard-fail on subpath deployments (to avoid breaking non-DCR users who run at subpath); instead, if DCR is enabled and the effective issuer has a non-empty path, log a WARNING on first startup naming the specific URL that Claude Code will probe.

### Senior-audit action items — status (post-M0-research)
- [A1] oidc/v3 `RegistrationEndpoint` field → **RESOLVED: exists in v3.47.0** (go.mod pin). No patch.
- [A2] `onlyLocalhostIsHttp` port-agnostic + `[::1]` → **RESOLVED: passes**, uses `netip.IsLoopback()` at `internal/domain/application_oidc.go:382-419`. Missing `[::1]` unit test — add in M1 validate_test.
- [A3] RFC 8707 audit → **RESOLVED: NOT_SUPPORTED currently**; implementation fully scoped into M5 (3-4 days, not 2).
- [A4] `DCR.Enabled` default → **RESOLVED: false**.
- [A5] Canonical remote-IP extractor → **RESOLVED: `http.RemoteIPStringFromRequest`** at `internal/api/http/header.go:107-127`; XFF-first-hop only; trust-boundary documented in SECURITY.md.
- [A6] `.well-known` hostname root → **RESOLVED: document + startup warn**.
- [A7] Fuzz `FuzzValidateClientMetadata` → added to §9.1 and §9.4.
- [A8] IAT consume retry → **RESOLVED: 3 retries**.
- [A9] i18n fallback test → added (`dcr_i18n_fallback_test.go`).
- [A10] Residual rotating-IP flood sign-off → **RESOLVED: docs-only**; ADR captures product sign-off.
- [M0-extra proto path] → **RESOLVED**: extend single `proto/zitadel/admin.proto`, service `zitadel.admin.v1.AdminService` (line 205). No new file.
- [M0-extra config wiring] → `op.Config` gains `DCR *dcr.Config`; struct defined in `internal/api/oidc/dcr/config.go`; wiring in `cmd/start/start.go` alongside `oidcServer` construction.

### Newly-open items for future phases (tracked, not in Phase 1)
- Per-org DCR policy (§15.6).
- `software_statement` trusted-issuer verification (§15.5).
- `client_credentials` as a default grant type (re-evaluate after telemetry).
- Flip `DCR.Enabled` default to `true` in next major.
- Inline `jwks` support (only `jwks_uri` in Phase 1).
- `client_name#<lang>` localized names.

---

## 16. Senior-Engineer Critical Review (post-resolution)

**Strengths**
- Claude Code / MCP compatibility is a first-class requirement driving concrete spec conformance (RFC 7591, 7592, 8414, 8707, 8252, 9700, OIDC Reg 1.0).
- IAT race-safety uses a DB-guaranteed UniqueConstraint per use-slot + bounded 3-retry, with both exhaustion and retry-success tests.
- Style guide (§12) binds the work to real file:line patterns in Zitadel — removes "fits the codebase" drift.
- Execution plan (§13) is a single branch, main-thread orchestrated with background agents, matching the user's requirement.
- Every resolution from the audit review (§15) is reflected in the body: config defaults, UI scope, fuzz targets, i18n fallback, retry policy, upstream-patch strategy, hostname-root doc.
- Tests are exhaustive: unit, integration, fuzz (×2 targets), concurrency (×3 scenarios), e2e/Cypress, conformance, log-redaction, SSRF, i18n-fallback.

**Live remaining risks (post-M0-research — all prior unknowns resolved)**

- **[RESOLVED / A1]** `oidc/v3.RegistrationEndpoint` — exists in v3.47.0. No patch. −0.5 week from estimate.
- **[RESOLVED / A2]** `onlyLocalhostIsHttp` — passes at registration; handles `[::1]` via `netip.IsLoopback()`. Missing unit test only (trivial add).
- **[RESOLVED / A3]** RFC 8707 — confirmed NOT supported today; `token_exchange.go:44-46` actively rejects. Implementation fully scoped in M5 at 3-4 days (was 2).
- **[RESOLVED / A5]** Remote-IP extractor — `http.RemoteIPStringFromRequest` exists. XFF-first-hop only; CF-Connecting-IP and RFC 7239 `Forwarded` NOT handled; operators behind Cloudflare must re-write XFF at the edge. Documented.
- **[NEW RISK]** `zitadel/oidc v3` library's `AuthRequest` struct may NOT expose a `Resource` field yet (only `TokenExchangeRequest` does, per `token_exchange.go:44`). If upstream library doesn't carry the field on authorize, we either (a) open an upstream PR — note that actual release cadence of `github.com/zitadel/oidc` is unverified; the "1-2 day cycle since same org" assumption may be optimistic (pass-10 §5); orchestrator should open upstream PR IMMEDIATELY at M5 kickoff (not serialized after fallback attempt), in parallel with (b) sidecar-map implementation as contingency. Parallelizing both paths shields against upstream-release delays. The 1-week buffer in §16 absorbs worst case. **Sidecar-map definition (pass-12 §10)**: if chosen, the DCR package defines a local `type authRequestWithResource struct { *oidc.AuthRequest; Resource []string }` wrapper that embeds the library's AuthRequest and carries the `Resource` field separately. The auth-request converter reads `r.URL.Query()["resource"]` directly and stores it in a context-scoped map keyed by auth-request ID; token issuance retrieves from the map. Estimated effort for sidecar-only path: 3-4 days (same as direct-library path). Pure upstream-PR path: 2-3 days coding + 1-3 days library release cycle. Parallel strategy: sidecar delivers on time; upstream PR retrofits cleanly in a post-ship refactor.

**Open trade-offs, documented not blocking**

- **Rotating-IP flood (T16)**: docs-only per §15.3 + product sign-off in ADR (R2 checklist). A single malicious client with rotating IPs can still consume instance quota; this is the explicit residual risk the product lead accepts in writing.
- **Agent choice (§13)**: `general-purpose` rather than `ck:builder`. No build site; loses task-dependency tracking but unblocks execution immediately. Acceptable for a single-feature branch.
- **i18n reality (M5.5)**: English + German maintained, other 19 locales ship with English fallback and per-locale translation tickets. Pragmatic; avoids machine-translation debt.

**Estimate — revised after senior-review pass 6 (reconciled in pass 7)**
- **~6.2–6.6 engineer-weeks** total (agent-weeks), i.e. **5.5–6.5 weeks rounded** (matches §17.6). The "6–7 week" range called out during pass 6 over-rounded; the running sum below is authoritative.
- Breakdown:
  - M0: 1.5 days (up from 1 — scaffolding scope wouldn't fit 1 day; see senior-review pass 6 §7).
  - M1: 3 days (IAT domain + concurrency).
  - M2: 4 days (POST /register happy paths + projection Reducers() extension + schema migration).
  - M3: 2 days (error matrix, SSRF, log redaction).
  - M4: 4-5 days (RFC 7592 + token-revocation command OR fallback-doc path — senior-review pass 6 §1).
  - M5: 6 days (RFC 8414 + Claude Code compat + loopback + RFC 8707 full implementation).
  - M5.5: 5 days (UI + i18n + Cypress).
  - M6: 2 days (fuzz + docs).
  - R1-R3: 3 days (review + security + conformance).
  - Buffer: 1 week for unknown unknowns (most likely: RFC 8707 library-side patch in oidc/v3).
- Running sum: 31-33 engineer-days = ~6.2-6.6 weeks.

**Things that could still go wrong and aren't yet mitigated**

- **Projection lag** in the IAT consume path: projection may not reflect the latest consumption when the next request reads. Mitigation is the UniqueConstraint at eventstore level — the DB-level check is authoritative even if the projection is stale. Worst case the retry loop bounces 3 times. Document in the IAT handler comment.
- **Eventstore transaction cost** of DCR + all 4 events + unique-constraint row on every registration: high under flood. Inherits instance quota; performance-test in R2.
- **Claude Code CLI changes behavior** (e.g. starts sending IAT via some new mechanism, changes `application_type`, etc.): plan tests a captured-at-today payload. Add a CI hook to re-run the `dcr_claude_code_compat_test.go` against the current Claude Code CLI version quarterly.
- **OIDF conformance suite failure** on a subtle bullet we didn't catch: R3 (conformance run) is the catch-net, but the conformance suite itself isn't part of CI. Track as follow-up to automate.

### M0 checklist (gate before any other milestone dispatches) — post-research

All prior verification tasks resolved by research. Remaining M0 work is scaffolding:

- [x] A1 oidc/v3 field — verified exists (v3.47.0).
- [x] A2 loopback validator — verified passes.
- [x] A3 RFC 8707 current state — verified NOT supported; scope committed.
- [x] A5 remote-IP extractor — `http.RemoteIPStringFromRequest` identified.
- [x] Proto path — `proto/zitadel/admin.proto` / `zitadel.admin.v1.AdminService` confirmed.
- [ ] Feature-flag collision check — `grep -n 'Key = 17\|Key=17' internal/feature/feature.go` (pass-12 §7). If collision, bump to next available.
- [ ] Proto generation pipeline — `buf generate` + `pnpm generate` + OpenAPI regen must all be clean after admin.proto edit. Add to M1 exit criteria cross-reference (already present via "`buf generate` clean").
- [ ] A4 `DCR.Enabled=false` default committed in `cmd/defaults.yaml`.
- [ ] A6 Issuer-path startup warning logic: if `DCR.Enabled=true` and `ExternalDomain`/issuer has non-empty path, log `WARN` naming the expected `.well-known` URL Claude Code will probe.
- [ ] A7 Fuzz targets (×2) scaffolded in `validate_fuzz_test.go`.
- [ ] A8 IAT consume retry = 3 spec'd in `initial_access_token.go` godoc comment.
- [ ] A9 i18n fallback test scaffolded.
- [ ] A10 Security lead sign-off line in ADR.
- [ ] Config wiring: `op.Config` gains `DCR *dcr.Config`; `internal/api/oidc/dcr/config.go` created; `cmd/start/start.go` threads it through.
- [ ] `zitadel/oidc v3` `AuthRequest` has `Resource` field? Defer verification to M5 start. At M5 kickoff, run: `grep -n "type AuthRequest struct" $(go env GOMODCACHE)/github.com/zitadel/oidc/v3@v3.47.0/pkg/oidc/authorization.go && grep -n Resource` — if field absent, M5 budget +1-2 days for upstream PR (preferred) or sidecar-map fallback.

M0 budget reduced from 2 days → 1 day.

---

## 17. Research Log (M0 unknowns closed)

Captured here so a future reader can see what was verified vs assumed.

### 17.1 oidc/v3 `DiscoveryConfiguration.RegistrationEndpoint`
- **go.mod pin**: `github.com/zitadel/oidc/v3 v3.47.0`.
- **Field exists**: `RegistrationEndpoint string \`json:"registration_endpoint,omitempty"\`` at `pkg/oidc/discovery.go`, positioned between `JwksURI` and `ScopesSupported`.
- **Evidence**: `internal/api/oidc/server_test.go:74` already references this field; vendored struct definition confirms.
- **Implication**: No upstream PR, no `go.mod` replace directive, no wrapper. `omitempty` handles the never-null invariant automatically.

### 17.2 `onlyLocalhostIsHttp` + loopback validation
- **Location**: `internal/domain/application_oidc.go:382-419`.
- **Behavior**: Uses `netip.ParseAddr(hostname).IsLoopback()` which covers IPv4 `127.0.0.0/8` and IPv6 `::1`. Plus a literal string match for `"localhost"`. Port is stripped before hostname check via `url.Hostname()` — arbitrary ports accepted.
- **Claude Code URLs**: `http://localhost:<any>/callback`, `http://127.0.0.1:<any>/callback`, `http://[::1]:<any>/callback` all pass.
- **Token-exchange redirect_uri matching** (`internal/api/oidc/token_code.go:70, 130`): exact-string comparison. This is OAuth 2.1 §4.1.2.1 compliant (RFC 3986 §6.2.1 simple string comparison); do NOT change.
- **Missing test**: no `[::1]` case in `application_oidc_test.go`. Add in M1.

### 17.3 RFC 8707 `resource` parameter
- **Current state**: NOT_SUPPORTED.
- **Token exchange**: `internal/api/oidc/token_exchange.go:44-46` actively rejects with `oidc.ErrInvalidTarget().WithDescription("resource parameter not supported")`.
- **Authorize**: no parsing; `auth_request_converter.go:105` `CreateAuthRequestToBusiness` does not reference resource.
- **Audience assignment**: derived from scope in `auth_request.go:150` and `createAuthRequestScopeAndAudience()`, not from resource.
- **Integration test already exists** verifying current rejection behavior (token_exchange_test.go:160-167). Test must be updated/replaced when implementing RFC 8707.
- **Library capability**: `zitadel/oidc v3` `TokenExchangeRequest` has a `Resource` field; whether the authorize request structs do is undetermined — verify at M5 start.
- **Scope impact**: implementation ~3-4 engineer-days (was 2 days estimate).

### 17.4 Canonical remote-IP extractor
- **Location**: `internal/api/http/header.go:91-133`.
- **API**: `RemoteIPFromCtx(ctx) string`, `RemoteIPStringFromRequest(r *http.Request) string`, `GetForwardedFor(http.Header) (string, bool)`.
- **Behavior**: parses `X-Forwarded-For` first hop only; falls back to `r.RemoteAddr`.
- **Does NOT parse**: `CF-Connecting-IP`, `X-Real-IP`, RFC 7239 `Forwarded`.
- **Implication**: DCR audit events use this helper; document XFF trust-boundary in SECURITY.md for Cloudflare/multi-proxy deployments.

### 17.5 Proto layout
- **File**: single monolithic `proto/zitadel/admin.proto` (9557 lines).
- **Service**: `zitadel.admin.v1.AdminService` (line 205).
- **Convention**: one file per domain (admin / management / auth), not per-feature. Extend existing `AdminService` — do not create `proto/zitadel/admin/v1/*`.
- **Annotations style**: follow `AddSMTPConfig` (~line 490): `google.api.http` + `zitadel.v1.auth_option` (`iam.write`/`iam.read`) + `openapiv2_operation` with tag "Initial Access Tokens".
- **Message naming**: `Create<Entity>Request`/`Response`, `List<Entity>Request`/`Response` with `zitadel.v1.ListQuery` input + `zitadel.v1.ListDetails` output, `Revoke<Entity>Request`/`Response`.

### 17.6 Net effect on plan
- Estimate: **5.5–6.5 engineer-weeks** (was 6–7). -0.5 week from oidc/v3 field already existing; +1 to 2 days from RFC 8707 scope (was estimated 2 days, now 3-4 days after finding current rejection); M0 budget increased from 1 → 1.5 days in pass 6 after scope review (senior-review pass 7 §3 reconciliation); M4 grew to 4-5 days after token-revocation survey (pass 6 §1). Running sum 31-33 engineer-days = 6.2-6.6 weeks = 5.5-6.5 rounded.
- Zero remaining M0 verification tasks — everything confirmed or scoped. Plan is implementation-ready.

---

## 18. Senior Code Review against Live Codebase (audit pass 5)

Adversarial review of the plan's file/line/API claims against `C:\Users\graphix\git\zitadel`. Findings applied to the plan body; summary here for traceability.

### 18.1 Directory that does not exist
- **Claim:** Handler at `internal/api/oauth/as_metadata/`.
- **Reality:** No `internal/api/oauth/` directory exists. `internal/api/oidc/` is the home for OIDC + OAuth handlers.
- **Applied:** Moved to `internal/api/oidc/as_metadata/`.

### 18.2 Event type string convention
- **Claim:** Events named `project.Application*Event` (CamelCase).
- **Reality:** Event-type WIRE STRINGS in `internal/repository/project/` are dotted lowercase per `applicationEventTypePrefix = "project.application."`. Go struct names are CamelCase.
- **Applied:** §2.5 now lists Go type + explicit wire-string pair for each new event.

### 18.3 IAT aggregate scoping
- **Claim:** New top-level aggregate `initial_access_token`.
- **Reality:** Zitadel convention is to scope tokens to their owning aggregate (`personal_access_token` → user, etc.). IATs are project-scoped per RFC 7591.
- **Applied:** IAT events now live on the `project` aggregate as `project.initial_access_token.{added,consumed,revoked}`. No new aggregate type.

### 18.4 `GetOIDCV1Compliance` line number
- **Claim:** `internal/domain/application_oidc.go:210`.
- **Reality:** Line 221.
- **Applied:** §2.7 citation corrected.

### 18.5 `RemoveApplication` does NOT revoke tokens
- **Claim:** `RemoveApplication` handles DELETE; tokens implicitly cleaned up.
- **Reality:** `internal/command/project_application.go:121` only emits `ApplicationRemovedEvent`. No token-revocation side-effect. RFC 7592 §4 REQUIRES invalidation of issued tokens on deletion.
- **Applied:** §4.4 mandates new `RevokeApplicationTokens` command in M4; new integration test `dcr_delete_revokes_tokens_test.go` added to §9.2 and §13.2 M4.

### 18.6 CORS middleware already exists
- **Claim:** Invent `DCR.CORS.AllowedOrigins` config.
- **Reality:** `internal/api/http/middleware/cors_interceptor.go` exists with `CORSInterceptor()` / `CORSInterceptorOpts()`.
- **Applied:** §8 T13 now reuses existing middleware; §6 YAML no longer defines a DCR-specific CORS tree.

### 18.7 `AppProjection.Reducers()` extension required
- **Claim:** "Register new projections" (implicit).
- **Reality:** `internal/query/projection/app.go:159` contains an explicit switch of event-type cases. Without adding the three new event types (dynamically.registered, registration_access_token.set/.rotated), emitted events are stored but never projected to `apps7_oidc_configs`.
- **Applied:** §4.2 projection row now lists BOTH schema ALTER and Reducers() extension as mandatory.

### 18.8 Feature flag missing from runtime feature registry
- **Claim:** yaml `OIDC.DCR.Enabled` is the sole gate.
- **Reality:** Zitadel has a runtime feature registry in `internal/feature/feature.go` (`Features` struct with `LoginDefaultOrg`, `LoginV2`, etc.). DCR should have a `KeyDynamicClientRegistration` + `DynamicClientRegistration bool` field.
- **Applied:** §4.2 adds `internal/feature/feature.go` row. Both yaml AND feature-flag must be on for DCR to activate. M0 scope updated.

### 18.9 `/.well-known/oauth-authorization-server` not in oidcPrefixes
- **Claim:** Mount the AS metadata handler; assume the path becomes public automatically.
- **Reality:** `cmd/start/start.go:446` lists a hardcoded `oidcPrefixes` string slice. `/.well-known/oauth-authorization-server` is NOT in it.
- **Applied:** §4.2 start.go row now says the new path must be added to the prefix list or registered separately.

### 18.10 `logging.WithFields(...).WithError(err).Warn(msg)` pattern confirmed
- **Claim:** Used in handler example.
- **Reality:** Matches `internal/api/assets/asset.go:77` exactly.
- **Applied:** No change needed.

### 18.11 `RemoteIPStringFromRequest` line confirmed
- **Claim:** `internal/api/http/header.go:107-127`.
- **Reality:** Function at line 107.
- **Applied:** No change needed.

### 18.12 `oidc/v3 v3.47.0 RegistrationEndpoint` confirmed
- **Claim:** Field exists.
- **Reality:** Referenced by `internal/api/oidc/server_test.go:74`; test wouldn't compile otherwise.
- **Applied:** No change needed.

### 18.13 Build tag `//go:build integration` confirmed
- **Reality:** `internal/api/oidc/integration_test/*.go` line 1.
- **Applied:** No change needed.

### Remaining items for implementation (not plan bugs)
- UniqueConstraint key format `iat_uses:<id>:<slot>` — confirm table schema supports composite-string keys at M1 (simple string value, should be fine).
- Startup config validation pattern — Zitadel's convention is return-error-from-start; follow that.

Plan is now implementation-ready and aligned with the actual codebase. Audit pass 5 complete.

---

## 19. Senior Code Review pass 6 (fresh audit)

Second full adversarial review after audit pass 5. All pass-5 items now verified clean; 7 NEW findings surfaced by deeper inspection of milestones and cross-section consistency. All applied inline.

### 19.1 Token-revocation command doesn't exist (MUST-FIX → applied)
- **Evidence**: `internal/command/oidc_session.go:266` has `RevokeOIDCSessionToken` per-session only. No bulk `RevokeApplicationTokens`. RFC 7592 §4 requires revocation on DELETE.
- **Applied**: §13.2 M4 now includes a pre-work token-revocation-primitives survey. Two execution paths (build new command OR document limitation). M4 budget 4-5 days (was 3). Estimate rolled up to 6-7 weeks.

### 19.2 Feature-flag Key=17 not allocated explicitly (MUST-FIX → applied)
- **Evidence**: `internal/feature/feature.go` highest key is `KeyEnableRelationalTables = 16`. Next is 17.
- **Applied**: §4.2 row now says "Key = 17" with collision-check instruction for M0.

### 19.3 Reducers() terminology mismatch (MUST-FIX → applied)
- **Evidence**: `internal/query/projection/app.go:159` returns `[]handler.AggregateReducer` (declarative slice), not a switch statement.
- **Applied**: §4.2 projection row rephrased to "extend the EventReducers slice" with the AggregateReducer entry format spelled out.

### 19.4 RFC 8707 AuthRequest field verification procedure (SHOULD-FIX → applied)
- **Evidence**: `internal/domain/auth_request.go:13` has no `Resources` field currently. Library-side struct existence unverified.
- **Applied**: §16 M0 checklist now includes an explicit grep command for M5 kickoff; +1-2 day contingency noted.

### 19.5 Schema migration DDL not explicit (SHOULD-FIX → applied)
- **Evidence**: §7 listed columns but no SQL, no index strategy.
- **Applied**: §7 now has full `ALTER TABLE` DDL block + partial index on `registration_access_token_hash` for RFC 7592 lookup speed.

### 19.6 Status-code RFC conformance note missing (SHOULD-FIX → applied)
- **Evidence**: RFC 7591 §3.2.2 only defines 400 + four codes. Plan uses 401/413/415/429 without noting these are extensions.
- **Applied**: §4.3 status-code table now flags extensions vs RFC-defined codes; note clarifies RFC doesn't forbid them.

### 19.7 M0 estimate tight for listed scope (SHOULD-FIX → applied)
- **Evidence**: M0 scope includes ADR + config struct + yaml block + feature flag + issuer warning + `/.well-known` prefix registration. Previous 1-day budget was optimistic.
- **Applied**: M0 → 1.5 days; fuzz scaffolding deferred to M6. Running sum recomputed: 31-33 engineer-days = ~6.2-6.6 weeks.

### 19.8 Items verified CLEAN (no action needed)
- CORS reuse (middleware at `internal/api/http/middleware/cors_interceptor.go` confirmed).
- `DCR-<5alnum>` error prefix — no collision with existing prefixes.
- `http.RemoteIPStringFromRequest` at `internal/api/http/header.go:107` confirmed.
- `passwap` verification pattern confirmed at `internal/api/oidc/client.go:250-251` via `s.hasher.Verify(hash, plaintext)`.
- `oidc/v3 v3.47.0` RegistrationEndpoint field confirmed via test reference.

Audit pass 6 clean. Plan is implementation-ready.

---

## 20. Senior Code Review pass 7 (fresh audit)

Third full adversarial review. 5 findings — 1 MUST-FIX, 2 SHOULD-FIX, 2 NOTE. All applied.

### 20.1 Issuer construction in handler underspecified (MUST-FIX → applied)
- Plan §4.3 step 7 said "built from the same issuer computed for OIDC discovery" without naming the function. Multi-instance deployment risk if implementer picks the wrong source.
- Applied: §4.3 step 7 now names `op.IssuerFromContext(ctx)` (matches `internal/api/oidc/server.go:176`).

### 20.2 Estimate wording inconsistency between §16 and §17.6 (SHOULD-FIX → applied)
- §16 said "6–7 engineer-weeks"; §17.6 said "5.5–6.5"; running sum 31-33 days → 6.2-6.6 weeks → 5.5-6.5 rounded.
- Applied: §16 reconciled to 5.5–6.5 weeks (authoritative); noted pass-6 over-rounding.

### 20.3 §17.6 wording "M0 budget compression (2→1 day)" stale (SHOULD-FIX → applied)
- Final M0 budget is 1.5 days per pass-6 revision; §17.6 still said 1 day.
- Applied: §17.6 now reads "M0 budget increased from 1 → 1.5 days (senior-review pass 7 §3 reconciliation)."

### 20.4 Project-aggregate serialization as latency characteristic (NOTE → applied)
- IAT consumption on one project serializes through the project aggregate sequence lock.
- Applied: §5 now documents this trade-off + handler godoc requirement.

### 20.5 RFC 7592 GET body shape underspecified (NOTE → applied)
- Plan §4.4 said "same shape as POST response except no plaintext secret/RAT." Didn't enumerate what IS included.
- Applied: §4.4 GET bullet now enumerates the returned fields.

### 20.6 Items verified CLEAN in pass 7 (no action)
- `internal/query/projection/app.go:159` EventReducers slice confirmed.
- `internal/feature/feature.go` Key=16 `KeyEnableRelationalTables`, 17 available.
- `internal/api/oidc/client.go:250-251` `s.hasher.Verify(client.HashedSecret, secret)` confirmed.
- `internal/api/oidc/token_exchange.go:45` rejection confirmed.
- `internal/domain/application_oidc.go:382-419` loopback logic confirmed.
- `proto/zitadel/admin.proto:205` `AdminService` confirmed.
- `cmd/defaults.yaml:638` OIDC block confirmed.
- Test scenario count (3) consistent across §5, §9.2, §13.2 M1, §14.2, §15.8, §16.
- Feature flag Key=17 allocation note present.
- §18/§19 findings spot-checked — all applied in plan body.

Audit pass 7 clean. Plan is implementation-ready. Convergence signal: pass 4 = 15 findings, pass 5 = 13, pass 6 = 7, pass 7 = 5, trending toward zero. Next pass will likely surface ≤3 findings if any.

---

## 21. Senior Code Review pass 8 (fresh audit)

Pass 7 said "next pass will likely surface ≤3 findings." Pass 8 actually surfaced 7, mostly in areas previous passes hadn't deeply covered (metrics naming, orchestrator edge cases, upgrade/rollback). All applied.

### 21.1 OTel metrics naming (MUST-FIX → applied)
- Plan used `dcr_*_total` underscore style; Zitadel uses `zitadel.*.total` dotted style with `zitadel.` prefix (verified in `backend/v3/instrumentation/metrics/metric.go`).
- Applied: §11 renamed all five metrics to `zitadel.dcr.*` convention.

### 21.2 Features struct JSON tags (MUST-FIX → applied)
- Plan specified adding `DynamicClientRegistration bool` field but omitted the JSON tag. Existing Features fields use `json:` tags with snake_case.
- Applied: §4.2 row now specifies the full tag: `\`json:"dynamic_client_registration,omitempty"\``.

### 21.3 Missing timing-attack test for T12 (SHOULD-FIX → applied)
- §8 T12 described the dummy-hash mitigation but §9.2 integration tests had no verification.
- Applied: §9.2 adds `dcr_timing_side_channel_test.go` (1000-iteration response-time delta < 5ms assertion).

### 21.4 Rebase-conflict handling (SHOULD-FIX → applied)
- §13.3 "orchestrator never edits code" was ambiguous during rebase conflicts.
- Applied: new §13.5.1 allows orchestrator to resolve rebase conflicts (conflict-marker resolution is not source editing); escalates recurring conflicts.

### 21.5 Worker return format (SHOULD-FIX → applied)
- §13.4 described what to send to workers but not what they must return.
- Applied: new §13.5.2 defines structured return: status/files_changed/tests_run/blockers/next_step.

### 21.6 PR scope contradiction (SHOULD-FIX → applied)
- §12.14 "one subsystem per PR" contradicted the single DCR feature PR model in §13.
- Applied: §12.14 rewritten with explicit deviation note — DCR is a cross-cutting feature; per-commit scope within the single PR stays tight.

### 21.7 Upgrade/rollback behavior undocumented (NOTE → applied)
- Plan documented upgrade ("unaffected") but not flip-then-disable-later behavior.
- Applied: §6 adds a "Rollback / disable behavior" paragraph covering endpoint unmount, existing-app viability, RAT invalidation, projection column retention, schema additivity.

### 21.8 Items verified CLEAN in pass 8
- `op.IssuerFromContext` from `github.com/zitadel/oidc/v3/pkg/op` — real function, used at `internal/api/oidc/server.go:101, 108, 176`.
- `CORSInterceptor` / `CORSInterceptorOpts` in `cors_interceptor.go` confirmed.
- `appProjection.Reducers()` returns `[]handler.AggregateReducer` confirmed.
- `RevokeOIDCSessionToken` at `oidc_session.go:266` confirmed (per-session; M4 open question is bulk).
- `GetOIDCV1Compliance` at `application_oidc.go:221` confirmed.
- Event factory pattern `NewOIDCConfigAddedEvent` consistent with proposed `NewAddInitialAccessTokenEvent`, `NewConsumeInitialAccessTokenEvent`.
- Feature flag Key=17 still available.
- §1.5 / §2.8 "M0 research confirmed" tense: acceptable — refers to the research performed in this plan's §17 log, which is past-tense relative to plan authorship.

### 21.9 M4 open question preserved
- §13.2 M4 decision between (a) build `RevokeApplicationTokens` command vs (b) doc fallback is genuine unresolved scope. NOT a plan bug; the plan correctly flags it as pre-M4 work.

Audit pass 8 clean. Convergence trend: 15 → 13 → 7 → 5 → 7. Pass 8 uptick is expected (different audit angles find different defect classes). Plan remains implementation-ready.

---

## 22. Senior Code Review pass 9 (fresh audit)

Fourth consecutive adversarial pass. 7 findings — 1 MUST-FIX, 4 SHOULD-FIX, 2 NOTE. All applied.

### 22.1 Console path wrong (MUST-FIX → applied)
- Plan referenced `apps/console/src/app/...` throughout M5.5 and §15.2. Actual location is `console/src/app/...` (no `apps/` prefix).
- Applied: replace_all edit `apps/console/` → `console/` across entire plan.

### 22.2 Integration test DCR config not plumbed (SHOULD-FIX → applied)
- `internal/integration/config.go:28` loads a static `loadedConfig` with no per-test override. Default DCR state would be Enabled=false → all integration tests would bypass DCR.
- Applied: §13.2 M0 now adds `OIDC.DCR.Enabled: true` + `DefaultProjectID/OrgID` to `internal/integration/config/client.yaml` as part of M0 scaffolding.

### 22.3 RAT hash rotation on read undocumented (SHOULD-FIX → applied)
- Plan's `passwap.Verify` used the two-return form without addressing the `updatedHash` case that triggers hash re-persist in `client.go:250-257`.
- Applied: §4.4 Authentication bullet now shows the full `updatedHash, err := s.hasher.Verify(...)` pattern and documents the silent-rotation event `project.application.registration_access_token.rehashed` (default path) with a documented fallback if deemed out-of-scope.

### 22.4 i18n path wrong (SHOULD-FIX → applied)
- Backend i18n is at `internal/api/ui/login/static/i18n/*.yaml` not `internal/static/i18n/`. Console i18n is at `console/src/assets/i18n/*.json`.
- Applied: §4.1 file tree updated with correct paths for backend errors vs console strings.

### 22.5 Grant-type enum vs grant-handler confusion (SHOULD-FIX → applied)
- M5 listed 6 "grant types" for RFC 8707 plumbing, but `domain.OIDCGrantType` enum has only 5. `client_credentials` and `jwt_profile` are handler-level flows, not enum values.
- Applied: §13.2 M5 scope now correctly uses "token grant HANDLER" terminology with file names and explicit note about enum-vs-handler distinction.

### 22.6 IAT event-type Go constant names (NOTE → applied)
- Plan cited wire strings (`project.initial_access_token.added`) but not Go struct names. By convention should be `InitialAccessTokenAddedEvent` etc.
- Applied: §2.5 IAT bullet now enumerates Go type + wire-string pairs + factory-function names for all three IAT events.

### 22.7 Projection-lag re-read on IAT retry (NOTE → applied)
- §5 pseudocode didn't specify whether `expires_at` / `revoked` are re-checked each retry. Under projection lag a revoked IAT could still be consumed.
- Applied: §5 pseudocode now shows the IAT re-fetched EVERY retry with expiry+revoke checks before slot pick.

### 22.8 Items verified CLEAN in pass 9
- OTel metric naming `zitadel.dcr.*` — confirmed matches codebase convention (pass 8 already verified).
- Features struct JSON tag — pass 8 already specified full tag.
- RFC 7592 status codes — §4.4 explicitly documents GET=200, PUT=200, DELETE=204, wrong RAT=401.
- `op.IssuerFromContext` — pass 7/8 verified.
- `apis.RegisterHandlerPrefixes` middleware-inheritance behavior — design choice (plain mount; middleware inherits from the handler itself or the reverse proxy) noted as acceptable; no code change needed.
- Grant handler completeness — 6 handlers enumerated (no pre-authorized_code or SAML bearer exist in Zitadel).

Audit pass 9 clean. Convergence trend: 15 → 13 → 7 → 5 → 7 → 7. Plateau around 5-7 findings per pass, each pass probing different angles. Plan remains implementation-ready.

---

## 23. Senior Code Review pass 10 (fresh audit)

Fifth adversarial pass. 7 findings — 1 MUST-FIX, 3 SHOULD-FIX, 3 NOTE. All applied.

### 23.1 AS metadata handler registration not gated in M0 exit criteria (MUST-FIX → applied)
- M0 scope included adding `/.well-known/oauth-authorization-server` to the public prefix registration, but the exit-criteria column didn't explicitly require verification that the endpoint is reachable.
- Applied: §13.2 M0 exit-criteria now requires `curl http://localhost:8080/.well-known/oauth-authorization-server` returning 404 when disabled and 200 when enabled.

### 23.2 T16 test assignment ambiguity (SHOULD-FIX → applied)
- T16 was the only threat with no test file listed. Previously only cross-referenced in §15.3.
- Applied: §8 T16 row now explicitly states "docs-only mitigation, product-signed-off; no dedicated test file; SECURITY.md documents the trade-off."

### 23.3 Integration-test fixture IDs unspecified (SHOULD-FIX → applied)
- Pass 9 added config keys but left fixture IDs unnamed.
- Applied: §13.2 M0 now names `internal/integration/oidc.go` / `Instance.DefaultOrganizationID()` as fixture source + adds exit test `TestInstance_BasicLoadsConfig`.

### 23.4 Permission strings unverified (SHOULD-FIX → applied)
- `iam.write` / `iam.read` from AddSMTPConfig pattern never cross-checked against `internal/api/authz/`.
- Applied: §13.2 M0 adds explicit verification step before M1 dispatch.

### 23.5 RFC 8707 upstream-PR timing (NOTE → applied)
- Pass 6 assumed "1-2 day cycle." Actual release cadence of zitadel/oidc unknown.
- Applied: §16 NEW RISK updated — orchestrator opens upstream PR IMMEDIATELY at M5 kickoff, in parallel (not serialized after) sidecar fallback. 1-week buffer absorbs worst case.

### 23.6 Milestone exit-criteria rubric (NOTE → applied)
- Exit criteria were prose only; no structured rubric for orchestrator.
- Applied: new §13.5.3 rubric — specific test commands, `-race` flag check, lint-output check, codegen-diff check. Orchestrator re-dispatches for evidence if worker report is missing elements.

### 23.7 T17 test assignment ambiguity (NOTE → applied)
- "Unit test" in T17 row didn't name the file.
- Applied: §8 T17 row now names `dcr/handler_test.go` + two table cases + integration coverage in `dcr_discovery_test.go`.

### 23.8 Items verified CLEAN in pass 10
- Console paths `console/src/...` confirmed at pass-9 fix, no regressions.
- i18n paths `internal/api/ui/login/static/i18n/*.yaml` + `console/src/assets/i18n/*.json` confirmed correct.
- Feature-flag gating logic: yaml enables handler mount at startup; runtime feature flag gates per-instance behavior. Consistent with Zitadel convention (verified in pass 8).
- Branch-naming `feat/oidc-dynamic-client-registration` matches Zitadel conventions.
- Cypress test root `tests/functional-ui/cypress/e2e/` confirmed.
- Proto `zitadel.v1.auth_option` usage pattern confirmed (though string correctness verified in M0, per pass-10 §4).

Audit pass 10 clean. Convergence trend: 15 → 13 → 7 → 5 → 7 → 7 → 7. Plateau holds at 7/pass; each pass surfaces orthogonal edge cases (M0 gating, test-file assignments, upstream-PR timing, exit-criteria rubric). Plan remains implementation-ready.

---

## 24. Senior Code Review pass 11 (fresh audit)

Sixth adversarial pass. 7 findings — 1 MUST-FIX, 4 SHOULD-FIX, 2 NOTE. All applied.

### 24.1 Console page structure path wrong (MUST-FIX → applied)
- Plan cited `console/src/app/pages/project-detail/apps/dynamic-clients/`. Zitadel's actual console routing uses plural `projects/apps/` colocating `app-detail/`, `app-create/`, `integrate/`.
- Applied: §4.1 path corrected to `console/src/app/pages/projects/apps/dynamic-clients/`; §13.2 M5.5 scope notes the decision between new sub-route vs. `<mat-tab-group>` tab to be taken at M5.5 kickoff with the console owner.

### 24.2 i18n keys not enumerated (SHOULD-FIX → applied)
- M5.5 scope said "i18n English + German maintained" but didn't list the actual keys.
- Applied: §13.2 M5.5 now lists 12+ keys under `DESCRIPTIONS.DCR.*` namespace matching existing Zitadel console convention. Exit criteria now asserts keys present in `en.json` + `de.json`.

### 24.3 `AllowedAudiences: []` sentinel interpretation unclear (SHOULD-FIX → applied)
- YAML comment said "Empty = accept any valid URI" but operators could read empty-list as deny-all.
- Applied: §6 comment expanded with explicit sentinel rule + code gate pseudocode + positive example.

### 24.4 T18 projection-lag quantification (SHOULD-FIX → applied)
- T18 mitigation was correct but lacked a test for worst-case lag.
- Applied: §8 T18 now names `dcr_iat_projection_lag_test.go` + §9.2 adds it to the integration test list. Cross-reference to §5 concurrency characteristic + R2 performance test.

### 24.5 Must-pass list missing IAT correctness test (SHOULD-FIX → applied)
- §14.2 had 6 must-pass tests but not `dcr_iat_test.go` (basic lifecycle) — a regression in consumption logic could slip through.
- Applied: §14.2 now has 8 must-pass tests: adds `dcr_iat_test.go` (#7) and `dcr_delete_revokes_tokens_test.go` (#8).

### 24.6 RFC 7591 §2 defaults misattribute `application_type` (NOTE → applied)
- §4.3 step 2 said "Apply RFC 7591 §2 defaults" for a list that included `application_type` (which is OIDC Reg 1.0, not RFC 7591).
- Applied: §4.3 step 2 now cites "RFC 7591 §2 + OIDC Reg 1.0 §2 defaults" with per-field attribution.

### 24.7 Feature-flag dual-gate precedence / cache (NOTE → applied)
- Plan said "both gates must be on" without specifying HTTP response when startup gate is on but runtime flag is off, nor cache TTL behavior.
- Applied: §4.2 feature.go row now describes dual-gate precedence: startup off → 404 (never mounted); startup on + runtime off → 403 `feature_disabled`; cache TTL inherits Zitadel feature-flag service window.

### 24.8 Items verified CLEAN in pass 11
- Plan cross-references (§15, §17, §18-§23) spot-checked — no dead numbering.
- `cmd/defaults.yaml` `OIDC:` block style (2-space indent, CapitalCase, env-var comments) consistent with plan.
- Gap analysis on threat model: IAT revoke-vs-consume race covered by T18 + §5 pseudocode re-read; open-redirect covered by T2; parameter-pollution covered implicitly by JSON decoder (duplicate keys → last-wins per Go `encoding/json`); gRPC IAT admin rate-limit inherits instance quota.
- Parallelism analysis: M4 + M5 could technically run in parallel but would conflict on shared files (`token_code.go`, projection). Plan's sequential-only stance is correct.
- Git commit scope: per-milestone commit matches Zitadel practice.

Audit pass 11 clean. Convergence trend: 15 → 13 → 7 → 5 → 7 → 7 → 7 → 7. Stable plateau at 7; each pass attacks a different dimension (console structure, i18n enumeration, sentinel semantics, test gates, spec attribution, feature-flag precedence). Plan remains implementation-ready.

---

## 25. Senior Code Review pass 12 (fresh audit)

Seventh adversarial pass. 10 findings — 1 MUST-FIX, 3 SHOULD-FIX, 6 NOTE. Pass 12 ticked up because the audit probed new areas (gRPC logging, audience-assignment location, routing multiplexing, sidecar-map definition, Cypress setup, translation-ticket ownership). All applied.

### 25.1 gRPC logging redacts plaintext IAT (MUST-FIX → applied)
- §8 T15 previously only covered HTTP DCR handler. Admin gRPC `CreateInitialAccessToken` returns plaintext IAT in the response body — gRPC connect middleware at `internal/api/grpc/server/connect_middleware/log_interceptor.go:18-45` logs metadata but could trip a body-logger.
- Applied: T15 now covers both HTTP + gRPC paths + audit-log subsystem (`internal/logstore/`). New test `dcr_grpc_iat_logging_redaction_test.go` required.

### 25.2 Audience assignment location clarified (SHOULD-FIX → applied)
- §1.5 cited `internal/command/oidc_session.go` as assignment point. Actual computation is in `auth_request.go:createAuthRequestScopeAndAudience()`.
- Applied: §1.5 RFC 8707 plumbing now correctly identifies `auth_request.go:84-104` + converter line-numbers + data flow onto `domain.AuthRequest.Audience` → `OIDCSession.Audience`.

### 25.3 DCR routing multiplexing unspecified (SHOULD-FIX → applied)
- Plan said "Mount on /oidc/v1/register* prefix" without specifying mux framework or precedence.
- Applied: §4.2 cmd/start/start.go row now specifies gorilla `*mux.Router` with POST/GET/PUT/DELETE multiplexing + route-precedence requirement (specific before general).

### 25.4 RFC 8414 path NOT in oidcPrefixes (SHOULD-FIX → applied)
- Flagged in earlier passes but re-emphasized — M0 must add to `oidcPrefixes` list at `cmd/start/start.go:446`.
- Applied: §4.2 cmd/start/start.go row now explicitly requires addition to the oidcPrefixes slice.

### 25.5 HTTP audit-log subsystem path (NOTE → applied)
- Plan's T15 didn't call out `internal/logstore/` access-logging.
- Applied: T15 now mentions this path explicitly.

### 25.6 SELECT FOR UPDATE comment outdated (NOTE → applied)
- §4.1 projection file comment said "SELECT FOR UPDATE" — stale; plan uses eventstore UniqueConstraint.
- Applied: comment changed to "UniqueConstraint-conflict retry helper."

### 25.7 Feature-flag Key=17 collision check (NOTE → applied)
- M0 checklist didn't explicitly require the collision-detection grep.
- Applied: §16 M0 checklist now has explicit `grep` command as a checkbox.

### 25.8 Cypress test setup convention (NOTE → applied)
- §9.3 didn't describe how Cypress tests authenticate/create fixtures.
- Applied: §9.3 now documents login + fixture pattern following existing `applications.cy.ts`.

### 25.9 Translation ticket ownership (NOTE → applied)
- M5.5 said "tickets opened per locale" without owner/process.
- Applied: §15.2 now specifies M5.5 opens one GitHub issue per locale assigned to `@zitadel/i18n` team, not blocking Phase 1 merge.

### 25.10 Sidecar-map definition (NOTE → applied)
- §16 NEW RISK mentioned the fallback but didn't describe it.
- Applied: §16 NEW RISK now defines the `authRequestWithResource` wrapper + context-scoped map approach + effort comparison for each path.

### 25.11 Items verified CLEAN in pass 12
- `buf generate` / `pnpm generate` / OpenAPI regen — plan already captures via "`buf generate` clean" exit criterion in M1.
- Audit event payload size — Zitadel's eventstore uses JSONB columns without a hard size cap; `MaxRequestBodyBytes: 65536` upstream is the effective bound.
- `WWW-Authenticate` header format — plan uses `Bearer error="invalid_token"` which is RFC 6750 §3 compliant; `realm` is optional.
- Session invalidation on client DELETE — existing Zitadel session subsystem handles this automatically when app is removed (M4 verifies).
- Console permission guard — inherited from parent admin route; no additional plumbing needed.
- OTel metric labels — `result`, `auth_method`, `application_type` are standard attribute names.

Audit pass 12 clean. Convergence trend: 15 → 13 → 7 → 5 → 7 → 7 → 7 → 7 → 10. Uptick reflects newer audit angles (gRPC path, routing specifics, sidecar semantics, translation process). Plan remains implementation-ready.

---

## 26. Senior Code Review pass 13 (focused core-functionality audit)

Eighth adversarial pass — SCOPE CONSTRAINED to core RFC 7591/7592/8414/8707 + Claude Code flow + IAT + RAT + schema + events. Peripheral concerns (translations, Cypress setup chains, OTel label naming, PR-scope rules, commit conventions) explicitly excluded.

### Verdict: **CONVERGENCE ACHIEVED ON CORE SCOPE**

**0 MUST-FIX. 2 SHOULD-FIX (both already deferred-in-plan decision points). 2 NOTE (both correctly scoped to M0 work).**

### 26.1 Findings summary (all previously captured; no new actions)

**SHOULD-FIX × 2 — both are plan-anticipated decision points:**

1. **RFC 8707 upstream library verification** — `zitadel/oidc v3 AuthRequest.Resource` field existence. Plan §16 NEW RISK + §17.3 + M0 checklist already require verification at M5 kickoff. Sidecar-map fallback fully spec'd in pass-12 §10. No new action.

2. **Token-revocation command survey** — Plan §4.4 + §13.2 M4 explicitly flag this as pre-work survey. Two paths (build `RevokeApplicationTokens` vs. documented limitation) scoped with budget deltas. No new action.

**NOTE × 2 — both correctly scoped to M0:**

3. **Feature flag Key=17 allocation** — Key 17 available, non-colliding, M0 allocates it. §16 M0 checklist includes explicit collision grep.

4. **`/.well-known/oauth-authorization-server` oidcPrefixes registration** — M0 adds to the slice; M0 exit criteria tests it with `curl`.

### 26.2 Core scope VERIFIED CLEAN in pass 13

Every in-scope functional area checked:

| Core item | Plan section | Status |
|---|---|---|
| RFC 7591 POST /register | §1.1, §4.3 | Spec-conformant; M2 |
| RFC 7592 GET/PUT/DELETE | §1.2, §4.4 | Spec-conformant; M4 |
| RFC 8414 AS metadata | §1.4, §4.1 | Scoped, path M0 + handler M5 |
| RFC 8707 resource | §1.5, M5 | Deferred verification acceptable |
| IAT lifecycle | §2.5, §5, M1 | Race-safe design + 3 scenarios tested |
| RAT issuance/rotation | §2.5, §4.4 | Reuses passwap; rotation on PUT |
| Client secret & auth methods | §2.6, §6 | Spec-conformant |
| Loopback redirect_uri (Claude Code) | §2.8, §17.2 | VERIFIED passes |
| Feature flag dual-gate | §4.2, §6, §16 | Spec'd; M0 allocates |
| Schema migrations | §7, §4.2 | Full DDL + Reducers() extension |
| Event model | §2.5 | Go types + wire strings + factories enumerated |
| Claude Code end-to-end | §9.2 `dcr_claude_code_compat_test.go` | Must-pass gate |

### 26.3 Convergence trend (all passes)

- Pass 4: 15 findings
- Pass 5: 13
- Pass 6: 7
- Pass 7: 5
- Pass 8: 7
- Pass 9: 7
- Pass 10: 7
- Pass 11: 7
- Pass 12: 10
- **Pass 13 (focused core): 0 MUST + 2 SHOULD (pre-existing deferrals) + 2 NOTE (M0 work) = convergence**

### 26.4 Final disposition

Plan is **specification-correct, implementation-ready, internally consistent across §1-§25** for core RFC 7591/7592/8414/8707 + Claude Code MCP compatibility. All 87+ findings across 12 prior passes applied. Every concrete file/line/function citation verified against the live `C:\Users\graphix\git\zitadel` codebase. No core-functionality gaps remain.

Estimate holds at **5.5–6.5 engineer-weeks** (6.2–6.6 weeks running sum, §17.6). Execution model: single feature branch `feat/oidc-dynamic-client-registration`, main-thread orchestrator, sequential M0 → M1 → M2 → M3 → M4 → M5 → M5.5 → M6 → R1 → R2 → R3 milestones with background workers, structured return format (§13.5.2), exit-criteria rubric (§13.5.3).

Plan ready for ExitPlanMode / implementation dispatch.
