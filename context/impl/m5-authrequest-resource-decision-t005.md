---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# T-005 — M5 Decision Gate: AuthRequest.Resource direct-vs-sidecar

Build site: context/plans/build-site.md
Cavekit: cavekit-rfc8707-resource.md R7 (+ R2 fallback clause)
Decision owner: DCR implementer (this loop)
Decision date: 2026-04-24

## Evidence

Command run against the pinned upstream module:

```bash
grep -n "Resource" /home/jeff/go/pkg/mod/github.com/zitadel/oidc/v3@v3.47.5/pkg/oidc/authorization.go
```

Output: **no match**. The `AuthRequest` struct at
`pkg/oidc/authorization.go:69` has Scopes, ResponseType, ClientID,
RedirectURI, State, Nonce, ResponseMode, Display, Prompt, MaxAge,
UILocales, IDTokenHint, LoginHint, ACRValues, CodeChallenge,
CodeChallengeMethod, RequestParam — **no `Resource` field**.

`go.mod` pins `github.com/zitadel/oidc/v3 v3.47.5`. No newer tag is in
the working module cache.

## Decision

**Path (b) — sidecar.** Implement T-012
(`authRequestWithResource` wrapper + context-scoped resource map) in
parallel with T-013 (upstream PR against `github.com/zitadel/oidc`
`AuthRequest`). The sidecar is the primary integration for Phase 1;
the upstream PR, once merged and the dependency bumped, lets us drop
the sidecar in a follow-up.

## Implications for downstream tasks

- **T-012**: create `type authRequestWithResource struct { *oidc.AuthRequest; Resource []string }` in the DCR domain (likely `internal/api/oidc/`) and a `context`-scoped `map[string][]string` keyed by auth-request ID.
- **T-013**: upstream PR against `github.com/zitadel/oidc`. This is a human-owned step — agents cannot open third-party PRs. Track in the DCR project issue / changelog. Once the PR lands and the dep is bumped, open a follow-up to remove the sidecar.
- **T-014**: `auth_request_converter.go` reads `r.URL.Query()["resource"]` directly (library does not surface it). After conversion, the converter stores the parsed `[]string` into the context-scoped map AND sets `domain.AuthRequest.Resources`.
- **T-027**: `OIDCSession.Audience` flow uses `domain.AuthRequest.Resources` as the source of truth — the sidecar map is a bridge for the library boundary, not the persistence hop.
- **T-045** (propagation to all 6 grant handlers): each grant handler retrieves the resource slice from the auth-request domain object (or from `r.Data.Resource` in grants that already have it, e.g., token_exchange). Sidecar map is only needed for `/authorize` flows that pass through the library `AuthRequest`.

## Deferred risk

If the upstream PR lands but the sidecar is forgotten, we ship redundant
code. Pin the follow-up to the same milestone as the next
`github.com/zitadel/oidc` bump.

## R7 acceptance-criteria mapping

- [x] Sidecar path selected based on `grep` evidence above.
- [ ] `authRequestWithResource` wrapper defined — deferred to T-012.
- [ ] Context-scoped map wired in converter — deferred to T-014.
- [ ] Token issuance retrieves from map — deferred to T-045.
- [ ] Upstream PR opened — deferred to T-013 (human-owned; current session
      cannot open PRs against a third-party repo autonomously).
