---
created: "2026-04-26T00:00:00Z"
last_edited: "2026-04-26T20:55:00Z"
---
# Implementation Tracking: DCR Register Handler

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-008 | DONE | Dual-gate handler mount. `internal/api/oidc/dcr/handler.go` stub: 403 `feature_disabled` (RFC 7591 envelope, no-store/no-cache headers, only the 2 RFC fields — no leakage) when runtime flag off, 200 placeholder body when both gates ON. `cmd/start/start.go` conditionally mounts `/oidc/v1/register` before `oidcPrefixes` so gorilla mux routes the more specific prefix. yaml off → mux 404. 4 subtests green. T-031 replaces the single HandlerFunc with method-aware mux routing. |
| T-044 | DONE (AC3 deferred to T-079) | TLS posture inspection (R10). AC1 (same TLS as /oidc/v1/userinfo) verified structurally — both mount on the same `apis` server in `cmd/start/start.go:693` and `:702`; `apis.RegisterHandlerOnPrefix` has no per-handler TLS override, so the entire API server's `config.TLS` / `config.ExternalSecure` posture is inherited. AC2 (no DCR-specific TLS knobs) pinned by new `TestDCRConfig_NoTLSKnobs_R10` in `internal/api/oidc/dcr_config_test.go` — reflection-based field scan over `DCRConfig` + `DCRJwksURIConfig` rejects any future field whose name contains TLS/Cert/HTTPS/Insecure/MTLS/Mtls. AC3 (deployment-guide TLS-termination note) deferred to T-079 (DCR MDX page) which owns the `cavekit-console-ui-docs-and-observability.md` R5 doc text. Inspection artifact: `context/impl/m_t044_tls_posture_inspection.md`. Test P. |
| T-031 | DONE | DCR mux router skeleton — promotes the T-008 single HandlerFunc to a gorilla `*mux.Router` multiplexing POST/GET/PUT/DELETE on `/oidc/v1/register{/*}`. Routes: POST `/` → register stub (T-033), GET/PUT/DELETE `/{client_id}` → 501 stubs (T-053/T-054/T-056). `featureGateMiddleware` wraps the entire router so the runtime feature flag fires BEFORE method routing — important so 403 responses don't leak the surface map (probing attacker can't distinguish "wrong method" from "wrong path" when gate is off). 405 handler returns RFC 7591 envelope with `error: "invalid_request"` for known paths called with wrong method. StrictSlash so empty + "/" both route to POST /. 7 method-routing subtests + 6 gate-overrides-routing cases pin the matrix. |
