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
- Human-owned carryover: T-069 (confirm console UI placement), T-075 (open 19 locale tickets) — flag these when resuming Tier 1+.
- T-013 previously human-owned — now CODE READY on `../oidc` branch `feat/authrequest-resource-rfc8707` (commit 1a138e7). Remaining human action: push branch + open upstream PR.

### Iteration 5 — 2026-04-26 (Tier 1 close-out — 9/9 done)
- T-014b: V2 login resource threading. `Resources` added to authrequest.AddedEvent (additive json:omitempty), command.AuthRequest, write model, reduce, conversion. WithResources fluent setter keeps the 25+ existing positional NewAddedEvent test call sites stable. 6 subtests green incl. back-compat unmarshal.
- T-008: dual-gate handler mount. dcr/handler.go stub returns 403 `feature_disabled` when runtime flag off, 200 stub when on; cmd/start/start.go conditionally mounts /oidc/v1/register before oidcPrefixes when yaml Enabled=true. 4 subtests green.
- T-015: SSRF-guarded JWKS fetcher. Full deny matrix (RFC 1918 / loopback / link-local incl. 169.254.169.254 / IPv6 ULA + link-local + loopback), DNS-rebind defense (single resolve per hop, pinned dialer), 3-hop redirect cap with per-hop re-validation, 1 MiB body cap, scheme guard, AllowLoopbackInDev override.
- T-016: 24 jwks_fetcher subtests covering deny matrix + redirect chains (3 OK / 4 refused) + redirect-trap to private IP + body cap (oversized + exact-at-limit) + literal-IP rejection + happy path. All green. dcr_ssrf_test.go integration test deferred to land alongside T-031/T-057 when the live register handler exists.
- T-011: IAT events on project aggregate. Added/Consumed/Revoked event types + factories + mappers + RegisterFilterEventMapper. Per-slot UniqueConstraint `iat_uses:<id>:<use_index>` for finite max_uses; nil constraint when max_uses=0. 9 subtests green incl. wire-type pin, finite-vs-unbounded constraint matrix, distinct-IAT-distinct-slot.
- Kit update: cavekit-discovery-and-as-metadata.md R4 absorbed runtime issuer-path warning (option ii from session Q3) — runtime check lives in T-030 handler where per-request issuer is available.
- Build site: T-014b inserted into Tier 1 (effort S, blocked by T-012 + T-014).
- Tier 1 status: 9/9 (or 10/10 incl T-014b). All builds and targeted tests green. F-001 still OPEN — ships when T-026/T-027 land in Tier 2.

### Iteration 4 — 2026-04-24 (Tier 1 — 4/9 done)
- Pre-flight: Fixed "missing generated proto packages" tree-gap. They are gitignored; `nx run @zitadel/api:generate-stubs generate-assets generate-statik` regenerates. `go build ./cmd/... ./internal/... ./pkg/...` clean. `backend/main.go` has a pre-existing commented-out `main()` making `go build ./...` fail — same at cc74a36b6, not caused by this work.
- T-009: DONE — DCRConfig.Validate startup refuse on empty defaults in anonymous mode. 7 subtests green.
- T-010: DONE (with R5 deviation doc) — WARN on ExternalDomain-with-slash. Kit's "issuer=URL" assumption doesn't match Zitadel's hostname-only ExternalDomain; runtime check lands with T-029/T-030. 5 subtests green.
- T-012: DONE — RFC 8707 sidecar (context key + middleware + accessors). Installed in OIDC HTTP chain. 9 subtests green.
- T-014: DONE (V1 only) — domain.AuthRequest.Resources + converter wire-through. V2 login path (command.AuthRequest via authrequest.AddedEvent) is out-of-scope; needs event-schema work. Flagged.
- Codex review (reminder): F-001 still OPEN — the T-004 accept-without-validation window remains until T-026/T-027 land. Tier 2 closure plan: bundle T-026/T-027 so `/authorize` resource flow ships correct; T-045 fills token-exchange `aud` at Tier 3.

### Iteration 3 — 2026-04-24 (cross-repo pivot: upstream oidc library)
- Scope expansion: user scoped ../oidc into the build. Ran minimal ck:init + targeted research on pkg/oidc/authorization.go + pkg/op/auth_request.go.
- New cavekit at ../oidc/context/kits/cavekit-authrequest-resource.md (R1..R5, 5 tasks all Small).
- New build-site at ../oidc/context/plans/build-site.md (O-001..O-005, 3 tiers).
- Executed full 5-task build:
  - O-001: AuthRequest.Resource field + json/schema tags — DONE (pkg/oidc/authorization.go).
  - O-002: CopyRequestObjectToAuthRequest carries Resource — DONE (pkg/op/auth_request.go).
  - O-003: TestAuthRequest_DecodeResource (absent/single/multiple) — DONE, green.
  - O-004: TestCopyRequestObjectToAuthRequest_Resource (copy/leave-existing) — DONE, green.
  - O-005: go build ./... + go test ./... green; struct-literal audit clean.
- Tier-0 codex peer review finding F-001 updated: Option D added (land upstream PR → bump dep → wire propagation).
