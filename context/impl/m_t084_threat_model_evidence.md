---
created: "2026-04-27T18:30:00Z"
last_edited: "2026-04-27T18:30:00Z"
---
# T-084 — DCR Threat-Model T1–T20 Evidence Map

**Source kit:** `context/kits/cavekit-security-hardening.md` R6.

This is the authoritative evidence map for the DCR Phase-1 threat
model. T-083 (SECURITY.md threat-model subsection) and T-085 (ADR
§T16 product sign-off) consume this artifact verbatim — keep the
table here in lockstep with their published forms.

Each row maps:

- **T-id** — threat label from `context/refs/dcr-plan.md` §8.
- **Threat** — short description.
- **Mitigation type** — `config` / `code` / `docs` / `mixed`.
- **Source** — file paths or symbol names that implement / document
  the mitigation. Line numbers omitted where they would couple this
  artifact too tightly to short-term refactors; the symbols stay
  stable.
- **Test evidence** — test file(s) that pin the mitigation. `n/a`
  is reserved for docs-only mitigations.
- **Build-site task** — the task that delivered the mitigation.

---

## T1–T20 Evidence Table

| T-id | Threat | Mitigation type | Source | Test evidence | Task(s) |
|------|--------|----------------|--------|---------------|---------|
| **T1** | Unauthenticated registration spam (IAT-off mode). | mixed | `cmd/defaults.yaml` `OIDC.DCR.MaxRequestBodyBytes`; instance-level access quota inherited from `limitingAccessInterceptor` (`cmd/start/start.go` `limitingAccessInterceptor.Handle(dcr.NewHandler(...))`). | `internal/api/oidc/dcr/decode_test.go` (413 path); 429 path runs in integration only (T-043 inherits from `limitingAccessInterceptor`). | T-001, T-043 |
| **T2** | Phishing-grade `redirect_uri` registration. | mixed | Per-project isolation via `RegisterClient` writing on the project aggregate (`internal/command/dynamic_client_registration.go`); user-consent flow lives outside DCR; `OIDC.DCR.AllowedRedirectURIHostPatterns` allow-list (`internal/api/oidc/dcr/validate.go` redirect-URI host-pattern check); audit-log row carries `RemoteAddrSHA256` + `UserAgent` (`internal/repository/project/dynamic_client_registration.go` `ApplicationDynamicallyRegisteredEvent`). | `internal/api/oidc/dcr/validate_test.go` host-pattern matrix; `internal/command/dcr_audit_payload_test.go` audit-field pin. | T-001, T-034, T-040, T-068 |
| **T3** | Public-client downgrade (`auth_method=none` without PKCE). | code | PKCE S256 enforced via `domain.GetOIDCV1Compliance` integration in `validate.go` `CheckRedirectURIs`; secret-matrix in `validate.go` rejects `client_secret_jwt` and gates `private_key_jwt` on `jwks_uri`. | `internal/api/oidc/dcr/validate_test.go` R5 auth-method matrix (6-row + blank-jwks-uri). | T-034, T-036 |
| **T4** | RAT leakage at rest or in transit. | code | RAT plaintext is the only one-time emission (`response.go` `WriteRegistrationResponse`); persisted state is Passwap-encoded hash via `ApplicationRegistrationAccessTokenSetEvent`; PUT rotates RAT atomically via `ApplicationRegistrationAccessTokenRotatedEvent`; silent rehash event on algo drift. | `internal/api/oidc/dcr/manage_test.go` (`TestVerifyRAT_*`); `internal/command/dynamic_client_registration_test.go`; `internal/api/oidc/dcr/manage_put_test.go`. | T-040, T-051, T-055 |
| **T5** | IAT replay beyond `max_uses`. | code | Eventstore `UniqueConstraint` per slot (`iat_uses:<id>:<idx>`) on `InitialAccessTokenConsumedEvent`; 3-retry loop in `command.ConsumeInitialAccessToken`; admin `RevokeInitialAccessToken`. | `internal/api/oidc/dcr/dcr_iat_concurrency_test.go` (10/3, 4/4, 5/4 race scenarios `-count=1000`); `internal/command/dcr_iat_projection_lag_test.go` (Monte Carlo ≥95%). | T-011, T-017, T-018, T-060 |
| **T6** | `software_statement` algorithm confusion. | mixed | Feature off by default (`cmd/defaults.yaml` `OIDC.DCR.SoftwareStatement.Enabled: false`); validate.go rejects with `unapproved_software_statement` when statement supplied while feature off. | `internal/api/oidc/dcr/validate_test.go` software-statement-while-disabled test. | T-001, T-034 |
| **T7** | RFC 7592 manage-endpoint enumeration via 404. | code | Anti-enum dummy-Verify on unknown `client_id` (`manage.go` `VerifyRAT` NotFound branch); WWW-Authenticate header on every 401; `Cache-Control: no-store` on the 401 to block CDN-pinned signal. | `internal/api/oidc/dcr/manage_antienum_test.go` (9-row matrix + dummy-hash source contract + no-cache pin). | T-052 |
| **T8** | SSRF via `jwks_uri` fetch. | code | `internal/api/oidc/dcr/jwks_fetcher.go` enforces RFC1918 / loopback / link-local / IPv6 ULA deny matrix; DNS-rebind defense (single-resolve + pinned-IP dial); 3-hop redirect cap with per-hop re-validation; 1 MiB body cap; `OIDC.DCR.JwksURI.AllowLoopbackInDev` override. | `internal/api/oidc/dcr/jwks_fetcher_test.go` (24 deny-matrix subtests, redirect-trap, body-cap). | T-015, T-016 |
| **T9** | Stored XSS via `client_name` / `logo_uri`. | mixed | Untrusted display-only contract: console template-escapes; `logo_uri` is NOT auto-fetched. | console XSS escape coverage in T-070 cypress (deferred — UI tier). | T-070 (frontend, blocked on T-069) |
| **T10** | Over-broad grant types via registration. | code | Server-side intersection with `OIDC.DCR.AllowedGrantTypes` / `AllowedResponseTypes` / `AllowedAuthMethods` / `AllowedApplicationTypes` in `validate.go` `ValidateAndClampMetadata`. | `internal/api/oidc/dcr/validate_test.go` intersection matrix (R4 13 ACs). | T-034 |
| **T11** | Cross-tenant escalation via IAT replay across instance/org/project. | code | IAT carries `{instance_id, org_id, project_id}` on event payload + projection (`internal/repository/project/iat.go` + `internal/query/projection/initial_access_token.go`); ResolveIAT cross-instance check (`auth.go`); ConsumeIAT operates on the IAT's project aggregate. | `internal/api/oidc/dcr/auth_test.go` (T-064 cross-tenant subtests: cross-instance reject + cross-org RegistrationContext binding + dummy-Verify timing-match on cross-instance). | T-037, T-064 |
| **T12** | Timing side-channel — known-vs-unknown `client_id` on RFC 7592. | code | Anti-enumeration pre-computed dummy hash (`BuildAntiEnumDummyHash`); both branches run a real Passwap `Verify` against either the stored hash or the dummy; algorithm-mismatch panic at startup if config drifts (F-101 guard). | `internal/api/oidc/dcr/dcr_timing_side_channel_test.go` (50-iter real-bcrypt, ratio bounded `[0.5, 2.0]`; observed 1.000). | T-052, T-058 |
| **T13** | CSRF on DCR endpoints. | mixed | CORS interceptor reused from existing OIDC chain (`internal/api/http/middleware/cors_interceptor.go` mounted via `dcr.NewHandler` wrapping); no DCR-specific CORS knob; never `Allow-Origin: *` + `Allow-Credentials: true`. | T-003 inspection artifact (`context/impl/m0-cors-reuse-t003.md`); structural pin in dispatcher tests. | T-003, T-031 |
| **T14** | Proxy / CDN secret caching of registration responses. | code | `Cache-Control: no-store` + `Pragma: no-cache` set on every DCR response (POST 201 + GET 200 + PUT 200 + 401 anti-enum). | `internal/api/oidc/dcr/response_test.go`; `manage_get_test.go`; `manage_put_test.go`; `manage_antienum_test.go` no-cache pin. | T-042 |
| **T15** | Logs leak secrets (`client_secret`, RAT, IAT plaintext, `software_statement`). | mixed | `RedactSecrets` utility (`internal/api/oidc/dcr/redact.go`); HTTP + gRPC middleware logs DO NOT log bodies (M0 audit: `context/impl/m0-log-redaction-survey-t006.md`); `internal/logstore/` audited clean (`context/impl/m_t063_logstore_iat_audit.md`); existing `AccessLog.Normalize()` redacts `Authorization` + `Cookie`. | `internal/api/oidc/dcr/redact_test.go` (13 subtests + half-redaction-unsafe pin); `internal/logstore/record/access_test.go` (+IAT + RAT Bearer redaction). | T-006, T-061, T-062, T-063 |
| **T16** | Rotating-IP flood (single-IP rate-limit bypass via botnet rotation). | docs | Documented residual risk; product sign-off in ADR; SECURITY.md trade-off note. No dedicated test file (the mitigation is operational — IP-rotating attacks are a CDN/WAF concern). | n/a (docs-only mitigation). | T-083, T-085 |
| **T17** | OIDC discovery emits `"registration_endpoint": null` instead of omitting the key. | code | `omitempty` JSON tag drops the key when the dual-gate is off; never literal `null`; `as_metadata` mirrors the same field. | `internal/api/oidc/dcr/handler_test.go` `TestT065_RegistrationEndpoint_T17_DualState` (2 subtests: disabled→absent, enabled→absolute URL); `internal/api/oidc/dcr_discovery_test.go` byte-identity pin. | T-029, T-047, T-065 |
| **T18** | Projection lag on IAT consume causes false-success or double-consume. | code | Eventstore-level `UniqueConstraint` is authoritative (commit-time, not projection-time); 3-retry loop re-fetches projection between attempts; revocation/expiry observed pre-push. | `internal/api/oidc/dcr/dcr_iat_concurrency_test.go` race scenarios; `internal/command/dcr_iat_projection_lag_test.go` (Monte Carlo: 962/1000 = 96.2% success at lagProb=0.35). | T-017, T-018, T-060 |
| **T19** | Eventstore flood from a registration burst (write amplification). | mixed | Instance access quota inherited from `limitingAccessInterceptor` (T1); `MaxRequestBodyBytes` cap. Performance burst test deferred to T-067 dashboards (the `zitadel.dcr.errors_total` + `request_duration_seconds` metrics surface burst signal). | metrics layer pinned by `internal/api/oidc/dcr/dcr_otel_metrics_test.go`; runtime burst measurement is operations work. | T-001, T-016, T-067 |
| **T20** | Claude Code CLI changes registration payload shape. | code | Literal Claude Code MCP body locked in `dcr_claude_code_compat_test.go`; PKCE S256 follow-up flow asserted; quarterly CI re-run hook documented. | `internal/api/oidc/integration_test/dcr_claude_code_compat_test.go` (`//go:build integration`). | T-057 |

---

## Notes & open carryovers

- **T9** (stored XSS) implementation lives in the frontend (T-070);
  T-069 is the human-owned UI placement decision that gates T-070.
  Until T-070 lands, the threat model lists T9 as DOCS-MITIGATED
  (untrusted-display contract) with no automated test pin. The
  next /ck:make wave that picks up the frontend chain MUST add a
  cypress XSS-payload pin alongside T-070's view tests.
- **T16** (rotating-IP flood) intentionally has no automated test —
  the residual risk is what T-085's ADR captures. Do NOT promote
  this to a test-pinned mitigation without product sign-off; the
  mitigation chain (CDN / WAF / per-instance quotas) lives outside
  the DCR feature scope.
- **T19** (eventstore burst) — the kit lists "R2 performance test
  under burst" as the test evidence. We defer the dedicated burst
  test (no DCR-specific test framework today) to operations
  observability via `zitadel.dcr.errors_total{code=server_error}`
  + `request_duration_seconds` p99. Update this row if a synthetic
  burst harness lands in a future tier.
- Cross-references to `cavekit-security-hardening.md` R1–R5 are
  authoritative for the per-defence implementation detail; this
  table maps threats to those defences, not the reverse.

---

## Acceptance evidence

This file satisfies cavekit-security-hardening.md R6 ACs T1–T20 by
providing a one-row-per-threat trace from threat to mitigation to
test file. Build-site Coverage Matrix R6 rows for T1–T20 ALL
reference T-084 — keep that linkage. T-083 (SECURITY.md) renders
this table for the public-facing audit; T-085 (ADR) signs off T16
specifically.
