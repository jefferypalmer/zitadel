---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# Loop Log — DCR Build Site

Build site: context/plans/build-site.md

### Iteration 1 — 2026-04-24
- T-001: OIDC.DCR yaml block — DONE. Files: cmd/defaults.yaml. Build P (yaml-parse), Tests N/A. Next: T-002
- T-002: KeyDynamicClientRegistration=17 + Features field + enumer — DONE. Files: internal/feature/feature.go, internal/feature/key_enumer.go. Build P, Tests P (`go test ./internal/feature/...`). Next: T-003

### Iteration 2 — 2026-04-24 (Tier-0 close-out)
- T-003: CORS reuse inspection — DONE. Artifact: m0-cors-reuse-t003.md. No new CORS config. Next: T-004
- T-004: token_exchange resource-param rejection removed — DONE. Files: internal/api/oidc/token_exchange.go. Kit ref to existing test was stale (file not present); new coverage lands in T-046. Next: T-005
- T-005: M5 AuthRequest.Resource decision — DONE. Grep confirmed zitadel/oidc v3.47.5 lacks Resource field → sidecar path (b). Artifact: m5-authrequest-resource-decision-t005.md. T-013 (upstream PR) flagged as human-owned. Next: T-006
- T-006: M0 log-redaction survey — DONE. Artifact: m0-log-redaction-survey-t006.md. HTTP + gRPC middleware log NO bodies; AccessLog already redacts Authorization/cookie. T-061 defensive wrappers still required. Next: T-007
- T-007: M4 DELETE-revocation path decision — DONE. Path (a) RevokeApplicationTokens selected; RFC 7592 §4 REQUIRES language + existing event-sourcing primitives justify it. Artifact: m4-token-revocation-decision-t007.md. Next: (Tier-0 complete — stopping for user review per user option #1)

Tier 0 summary: 7/7 DONE (T-001..T-007). Stopping at tier boundary.
- Human-owned carryover: T-013 (upstream zitadel/oidc PR), T-069 (confirm console UI placement), T-075 (open 19 locale tickets) — flag these when resuming Tier 1+.
