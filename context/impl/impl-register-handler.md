---
created: "2026-04-26T00:00:00Z"
last_edited: "2026-04-26T00:00:00Z"
---
# Implementation Tracking: DCR Register Handler

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-008 | DONE | Dual-gate handler mount. `internal/api/oidc/dcr/handler.go` stub: 403 `feature_disabled` (RFC 7591 envelope, no-store/no-cache headers, only the 2 RFC fields — no leakage) when runtime flag off, 200 placeholder body when both gates ON. `cmd/start/start.go` conditionally mounts `/oidc/v1/register` before `oidcPrefixes` so gorilla mux routes the more specific prefix. yaml off → mux 404. 4 subtests green. T-031 replaces the 200-stub with real RFC 7591 POST handler. |
