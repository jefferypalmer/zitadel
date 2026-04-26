---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# Implementation Tracking: Security Hardening

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-003 | DONE | CORS reuse inspection. Decision artifact: `context/impl/m0-cors-reuse-t003.md`. DCR handlers will wrap in existing `middleware.CORSInterceptor`; no new config tree. `rs/cors` semantics under `AllowCredentials:true` + `AllowOriginFunc` satisfy R1 "never `*` + credentials". |
| T-006 | DONE | M0 log-redaction posture survey. Decision artifact: `context/impl/m0-log-redaction-survey-t006.md`. HTTP + gRPC middleware log NO bodies today; AccessLog already redacts Authorization/cookie headers; bodies not captured. T-061 still required for defensive redaction wrappers (protects against future debug-level logging). |
| T-015 | DONE | SSRF-guarded JWKS fetcher at `internal/api/oidc/dcr/jwks_fetcher.go`. CIDR deny-list via netip.Prefix, DNS resolved exactly once per hop with pinned dialer (DNS-rebind defense), 3-hop redirect cap with per-hop SSRF re-validation, 1 MiB body cap, configurable HTTPTimeout, AllowLoopbackInDev dev override. Public seams `resolve` / `dial` enable test injection without mocking net/http. |
| T-016 | DONE | 24 jwks_fetcher subtests covering full deny matrix (RFC 1918 / loopback / link-local incl. 169.254.169.254 metadata / IPv6 ULA + link-local + loopback), parseDeniedRanges dev-override, oversized body, exact-at-limit body, redirect chains (3 OK / 4 refused), redirect trap to private IP, DNS-rebind one-resolve guarantee, literal-IP rejection, scheme guard. dcr_ssrf_test.go integration test deferred to land with T-031/T-057. |
