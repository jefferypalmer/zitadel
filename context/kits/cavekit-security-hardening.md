---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-26T22:30:00Z"
complexity: complex
---

# Cavekit: Security Hardening (SSRF, Log Redaction, Timing Side-Channel, Threat Model T1–T20)

## Scope
Cross-cutting security hardening required by the DCR feature: (a) `jwks_uri` SSRF guard with DNS-rebind defense, redirect cap, size cap, and IP-range deny-list; (b) log redaction across the HTTP middleware AND the gRPC connect-middleware path AND the audit-log subsystem; (c) timing side-channel mitigation on RFC 7592 unknown-`client_id` (constant-time + dummy-hash); (d) CORS reuse from existing middleware; (e) hash-rotation handling on RAT/secret reads; (f) traceable evidence for threat-model entries T1–T20.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §8 (T1–T20 threats), §4.1 (`jwks_fetcher.go`), §15.3 (residual rotating-IP risk), pass-12 §1 (gRPC redaction)
- Spec references: RFC 7591 §5 (security), RFC 9700 (BCP), RFC 6750 §3 (`WWW-Authenticate`)

## Requirements

### R1: CORS reuses existing middleware
**Description:** No DCR-specific CORS configuration is introduced. The DCR HTTP handler wraps in the same `CORSInterceptor(...)` chain used by other public endpoints.

**Acceptance Criteria:**
- [ ] The DCR handler is wrapped by `internal/api/http/middleware/cors_interceptor.go` `CORSInterceptor()` / `CORSInterceptorOpts()`.
- [ ] No `OIDC.DCR.CORS` config tree exists.
- [ ] CORS responses NEVER include `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true`.
- [ ] If MCP Inspector requires per-endpoint origin overrides, those flow through the existing middleware's options, not through new DCR-specific config.

**Dependencies:** none.

### R2: `jwks_uri` SSRF guard
**Description:** A SSRF-guarded HTTP client at `internal/api/oidc/dcr/jwks_fetcher.go` is the ONLY path used to fetch `jwks_uri` content for DCR-registered clients. It enforces an IP-range deny-list, DNS-rebind protection, redirect cap, response-size cap, and timeout.

**Acceptance Criteria:**
- [ ] The fetcher is located at `internal/api/oidc/dcr/jwks_fetcher.go`.
- [ ] Configured `OIDC.DCR.JwksURI.DisallowedIPRanges` from `cavekit-config.md` R1 is enforced for both initial connection AND every redirect target.
- [ ] DNS-rebind mitigation: hostname is resolved once, the resolved IP is checked against `DisallowedIPRanges`, and the dialer connects to that resolved IP (not re-resolved on subsequent connections within the request).
- [ ] Redirects are followed at most 3 hops; each redirect target is re-validated against `DisallowedIPRanges`; >3 hops → fetch fails.
- [ ] Response body size cap: 1 MiB; oversized responses fail.
- [ ] Total HTTP timeout is `OIDC.DCR.JwksURI.HTTPTimeout` (default 10s).
- [ ] When `OIDC.DCR.JwksURI.AllowLoopbackInDev=true`, `127.0.0.0/8` and `::1/128` are removed from the effective deny-list (dev override only; production MUST leave false).
- [ ] Table-driven unit tests in `jwks_fetcher_test.go` cover RFC1918, link-local, IPv6 ULA, loopback, oversized bodies, and redirect traps.
- [ ] Integration test `dcr_ssrf_test.go` verifies that `jwks_uri` pointing at `169.254.169.254`, `127.0.0.1:<port>`, and DNS that resolves to a private IP are all rejected.

**Dependencies:** `cavekit-config.md` R1; `cavekit-register-handler.md` R5; `cavekit-manage-handler.md` R5.

### R3: Log redaction across HTTP, gRPC, and audit-log paths
**Description:** Plaintext secrets MUST NEVER appear in logs. Redaction covers the HTTP middleware, the gRPC connect-middleware, and the audit-log subsystem.

**Acceptance Criteria:**
- [ ] M0 inspects `internal/api/http/middleware/log_interceptor.go` and `internal/api/grpc/server/connect_middleware/log_interceptor.go` to determine current body-logging behavior.
- [ ] If either path logs request/response bodies, a redactor is added that strips `client_secret`, `registration_access_token`, `software_statement`, the `Authorization` header, and the `token` field on `CreateInitialAccessTokenResponse`.
- [ ] If bodies are not logged today, defensive redaction wrappers are added explicitly in the DCR HTTP handler AND the IAT admin gRPC handler.
- [ ] `internal/logstore/` HTTP access-logging subsystem is verified to NOT leak IATs.
- [ ] Integration test `dcr_log_redaction_test.go` captures handler logs and asserts no `client_secret` / RAT / IAT plaintext substrings appear.
- [ ] Integration test `dcr_grpc_iat_logging_redaction_test.go` (NEW) captures gRPC log output for `CreateInitialAccessToken` and asserts no plaintext `token` field appears.
- [ ] **IAT-token regex (added 2026-04-26 / cross-ref `cavekit-iat.md` R5).** The redaction pattern for IAT plaintext MUST match `zdiat_[^\s"',]+` (greedy through the `.` separator that delimits ID from random). Half-redacting (e.g. masking only the random portion) is unsafe — combining a log-leaked ID with a separately-leaked random reconstructs the credential. The integration test `dcr_grpc_iat_logging_redaction_test.go` MUST include a case for a plaintext containing a literal `.` and assert the entire token is masked.

**Dependencies:** `cavekit-iat.md` R5, R6; `cavekit-register-handler.md` R7; `cavekit-manage-handler.md` R5.

### R4: Timing side-channel mitigation (T12)
**Description:** RFC 7592 unknown-`client_id` MUST take indistinguishable time from wrong-RAT-on-known-`client_id` so an attacker cannot enumerate `client_id`s by response-time observation. Achieved via constant-time Passwap `Verify` against a stored hash for known IDs and against a static dummy hash for unknown IDs.

**Acceptance Criteria:**
- [ ] On unknown `client_id` the handler still calls `passwap.Verify` against a static dummy hash before returning 401.
- [ ] Integration test `dcr_timing_side_channel_test.go` issues 1000 RFC 7592 GETs against (a) a known-valid `client_id` with a wrong RAT and (b) a nonexistent `client_id` with any RAT.
- [ ] Test asserts the mean and p95 response-time delta between (a) and (b) is below a tight bound (e.g., < 5ms).
- [ ] Test failure causes CI to fail.

**Dependencies:** `cavekit-manage-handler.md` R3.

### R5: Hash rotation on RAT / secret reads
**Description:** Passwap's `Verify` returns an `updatedHash` when the underlying algorithm has rotated. The handler MUST persist the new hash silently (without exposing rotation to the client).

**Acceptance Criteria:**
- [ ] RFC 7592 verification path uses the two-return form `updatedHash, err := s.hasher.Verify(...)` (matches `internal/api/oidc/client.go:250-257`).
- [ ] When `updatedHash != ""`, a `project.application.registration_access_token.rehashed` event persists the new hash without changing the RAT plaintext (cross-ref `cavekit-manage-handler.md` R2).
- [ ] If the silent-rehash path is deemed out of scope at M4, the limitation is documented as: "RAT hash algorithm rotation only applies on the next PUT, not on GET verification" — decision recorded in M4 worker report.
- [ ] Integration test `dcr_iat_projection_lag_test.go` validates retry-success rate ≥ 95% under simulated worst-case projection lag (cross-ref `cavekit-iat.md` R7 / T18).

**Dependencies:** `cavekit-iat.md` R7; `cavekit-manage-handler.md` R2.

### R6: Threat-model T1–T20 evidence map
**Description:** Each threat from §8 of the plan must trace to a documented mitigation (config, code, or doc) and (where applicable) a test file.

**Acceptance Criteria:**
- [ ] T1 (unauth spam): instance access quota inherited; `MaxRequestBodyBytes` enforced; SECURITY.md mentions IAT-mode escape hatch.
- [ ] T2 (phishing redirect_uri): per-Project isolation; consent screen; `AllowedRedirectURIHostPatterns`; audit log includes source IP + UA. Residual risk documented in SECURITY.md.
- [ ] T3 (public client downgrade): PKCE S256 enforced when `auth_method=none` (`cavekit-register-handler.md` R5).
- [ ] T4 (RAT leakage): hashed at rest; rotated on every PUT; all RFC 7592 ops emit events.
- [ ] T5 (IAT replay): `max_uses` via UniqueConstraint (`cavekit-iat.md` R2); expiry; admin revoke.
- [ ] T6 (`software_statement` alg confusion): off by default; rejected with `unapproved_software_statement` when disabled.
- [ ] T7 (RFC 7592 enumeration): 401 (not 404) for unknown IDs and wrong RAT (`cavekit-manage-handler.md` R3).
- [ ] T8 (SSRF jwks_uri): R2 above.
- [ ] T9 (stored XSS via `client_name` / `logo_uri`): treated as untrusted display-only; console escapes; no auto-fetch of `logo_uri`.
- [ ] T10 (over-broad grants): server intersects with `AllowedGrantTypes`.
- [ ] T11 (cross-tenant escalation): IAT carries `{instance_id, org_id, project_id}`; tests in `dcr_iat_test.go` cover cross-instance / cross-org abuse.
- [ ] T12 (timing side-channel): R4 above.
- [ ] T13 (CSRF): R1 above (CORS reuse).
- [ ] T14 (proxy/CDN secret caching): `Cache-Control: no-store, Pragma: no-cache` per `cavekit-register-handler.md` R7.
- [ ] T15 (logs leak secrets): R3 above.
- [ ] T16 (rotating-IP flood): docs-only mitigation; product-signed-off in ADR; SECURITY.md documents the trade-off; no dedicated test file.
- [ ] T17 (`registration_endpoint: null`): unit test in `dcr/handler_test.go` covers two cases (DCR disabled → key absent; DCR enabled → non-null absolute URL); integration coverage in `dcr_discovery_test.go` (cross-ref `cavekit-discovery-and-as-metadata.md` R3).
- [ ] T18 (projection lag on IAT consume): UniqueConstraint at eventstore commit is authoritative; 3-retry loop; `dcr_iat_projection_lag_test.go` validates ≥95% retry success under simulated lag.
- [ ] T19 (eventstore flood under burst): instance quota inherited; R2 performance test under burst.
- [ ] T20 (Claude Code CLI changes shape): `dcr_claude_code_compat_test.go` locks the payload (cross-ref `cavekit-register-handler.md` R9); CI hook re-runs quarterly.

**Dependencies:** R1, R2, R3, R4, R5; cross-cutting on every other DCR kit.

## Out of Scope
- WAF / reverse-proxy configuration (operator concern).
- Per-org SSRF deny-list overrides.
- DDoS mitigation beyond instance quota.
- Cryptographic primitive changes (Passwap is the chosen primitive).

## Cross-References
- See `cavekit-config.md` R1: `JwksURI.DisallowedIPRanges` defined here.
- See `cavekit-iat.md` R6: gRPC IAT plaintext response body must be redacted (R3).
- See `cavekit-iat.md` R7: project-aggregate serialization characteristic (T18 cross-ref).
- See `cavekit-register-handler.md` R5, R6, R7: PKCE enforcement, audit-event field redaction, no-store cache.
- See `cavekit-manage-handler.md` R2, R3: RAT verification + dummy-hash on unknown ID.
- See `cavekit-discovery-and-as-metadata.md` R3: T17 evidence.
- See `cavekit-console-ui-docs-and-observability.md` R3: SECURITY.md threat-model section + T16 sign-off.

## Source Traceability (brownfield)
- `internal/api/http/middleware/cors_interceptor.go` — `CORSInterceptor()` / `CORSInterceptorOpts()`. [VERIFIED] exists; reused by R1.
- `internal/api/http/middleware/log_interceptor.go` — HTTP access logging. [GAP] redaction unverified; M0 inspection task.
- `internal/api/grpc/server/connect_middleware/log_interceptor.go:18-45` — gRPC logging. [GAP] redaction unverified.
- `internal/logstore/` — audit-log subsystem. [GAP] IAT-leak audit unverified.
- `internal/api/oidc/client.go:250-257` — Passwap `Verify` two-return pattern. [VERIFIED] reference for R5.
- `internal/api/oidc/dcr/jwks_fetcher.go` — [GAP] does not exist; created by R2.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
