---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# Implementation Tracking: RFC 8707 Resource Indicators

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-004 | DONE | Removed `oidc.ErrInvalidTarget().WithDescription("resource parameter not supported")` rejection at `internal/api/oidc/token_exchange.go:44-46`. Replaced with a comment cross-referencing T-026 (allow-list) and T-045 (audience propagation). No existing test asserted the rejection behavior (kit reference `token_exchange_test.go:160-167` was stale — file does not exist); new coverage lands in T-046 `rfc8707_resource_test.go`. Compile validation deferred (pre-existing tree-level issue: generated proto packages missing — unrelated to T-004). |
| T-005 | DONE | M5 decision gate: grep confirmed `github.com/zitadel/oidc/v3 v3.47.5` `AuthRequest` struct does NOT have a `Resource` field (authorization.go:69). Decision: Path (b) sidecar. Artifact: `context/impl/m5-authrequest-resource-decision-t005.md`. T-012 (sidecar wrapper + context-scoped map) and T-013 (upstream PR, human-owned) run in parallel. T-013 cannot be auto-implemented; flagged. |
