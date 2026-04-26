---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# Implementation Tracking: RFC 8707 Resource Indicators

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-004 | DONE | Removed `oidc.ErrInvalidTarget().WithDescription("resource parameter not supported")` rejection at `internal/api/oidc/token_exchange.go:44-46`. Replaced with a comment cross-referencing T-026 (allow-list) and T-045 (audience propagation). No existing test asserted the rejection behavior (kit reference `token_exchange_test.go:160-167` was stale — file does not exist); new coverage lands in T-046 `rfc8707_resource_test.go`. Compile validation deferred (pre-existing tree-level issue: generated proto packages missing — unrelated to T-004). |
| T-005 | DONE | M5 decision gate: grep confirmed `github.com/zitadel/oidc/v3 v3.47.5` `AuthRequest` struct does NOT have a `Resource` field (authorization.go:69). Decision: Path (b) sidecar. Artifact: `context/impl/m5-authrequest-resource-decision-t005.md`. T-012 (sidecar wrapper + context-scoped map) and T-013 (upstream PR) run in parallel. |
| T-013 | CODE READY | Upstream PR against `github.com/zitadel/oidc` is CODE-COMPLETE at `/home/jeff/oidc` on branch `feat/authrequest-resource-rfc8707` (commit 1a138e7). Implements full library-side change (R1..R5 of `../oidc/context/kits/cavekit-authrequest-resource.md`): AuthRequest.Resource field, CopyRequestObjectToAuthRequest carry-forward, decoder + copy tests. `go build ./...` + `go test ./...` green. Remaining human action: push branch + open PR upstream (requires repo-write creds). Once merged and Zitadel bumps the dep past the merge SHA, T-012 sidecar becomes skippable. |
| T-012 | DONE | Sidecar implementation at `internal/api/oidc/rfc8707_sidecar.go`: `dcrResourceCtxKey` context key + `WithAuthorizeResources`/`ResourcesFromContext` accessors + `AuthorizeResourceSidecar` HTTP middleware. Installed in OIDC HTTP middleware chain at `op.go` so every `/oauth/v2` and `/oidc/v1` request carries the sidecar ctx downstream. 9 subtests covering context round-trip, middleware query-string / POST form extraction, body-consumption safety. Thread-local; no shared state. |
| T-014 | DONE (V1 only) | `domain.AuthRequest.Resources []string` field added. `CreateAuthRequestToBusiness` pulls from sidecar context and sets it. 3 subtests green. V2 gap addressed by T-014b. |
| T-014b | DONE | V2 login path resource threading. `Resources` added to `authrequest.AddedEvent` (additive json:omitempty — old events unmarshal with Resources=nil), `command.AuthRequest`, `AuthRequestWriteModel`, reduce path, `authRequestWriteModelToCurrentAuthRequest` conversion, and `createAuthRequestLoginClient` populates it from the sidecar context. `WithResources(r) *AddedEvent` fluent setter keeps the positional NewAddedEvent constructor stable for the 25+ existing test call sites. 6 subtests green: omitempty key absence, slice round-trip (nil/empty/single/multiple), back-compat unmarshal of pre-Resources events. |
