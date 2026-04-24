---
created: "2026-04-24T13:30:00Z"
last_edited: "2026-04-24T13:30:00Z"
---
# Codex Peer Review — Tier 0 Findings

Build site: context/plans/build-site.md
Tier: 0
Base ref: cc74a36b6 (pre-tier-0 main HEAD)
Reviewer: Codex gpt-5-codex
Review date: 2026-04-24

## Findings

| ID | Severity | File | Line | Description | Status |
|----|----------|------|------|-------------|--------|
| F-001 | P1 | internal/api/oidc/token_exchange.go | 44 | T-004 removed the `resource`-parameter rejection from `/token` token-exchange but the remainder of RFC 8707 (audience plumbing via T-014/T-027/T-045, allow-list validation via T-026) has not landed yet. Today a request with `resource=...` succeeds and mints a token whose `aud` claim never reflects the supplied resource — this is worse than the prior explicit `invalid_target` rejection per RFC 8707 §2 (AS should return `invalid_target` when it cannot honor the resource). Either keep rejecting until T-026/T-027/T-045 land, or accelerate the propagation pipeline so there is never a gap. | OPEN |

## Recommended remediation

Option A (revert + sequence): revert T-004 and land it together with T-026 at Tier 2 so the parameter is only accepted once the allow-list gate exists, then wire propagation at T-027/T-045.

Option B (accelerate): land T-026/T-027 (Tier 2) in the same tier cadence as T-004, i.e., bundle the gate + propagation so acceptance and enforcement ship together. T-045 (Tier 3) can follow separately since it only extends existing behavior to more grants.

Option C (interim gate): replace the removed rejection with a narrower interim rejection that (a) rejects syntactically invalid URIs with `invalid_target`, (b) accepts valid URIs but continues to omit them from `aud` until T-027 lands, and (c) ships a CHANGELOG / release-note warning flagging the interim gap.

Recommendation: **Option B** — bundling T-004 with T-026/T-027 into a single coherent change preserves RFC 8707 contract semantics at all tier boundaries. The build-site ordering that placed T-004 in Tier 0 and T-027 in Tier 2 introduces an unnecessary correctness gap across tier commits.

Decision owner: human (user). Waiting on direction before revert or bundling.

## Update (2026-04-24, post-T-013 code-ready)

T-013 (upstream `github.com/zitadel/oidc` PR) is now code-complete on
`../oidc` branch `feat/authrequest-resource-rfc8707`. Once that PR
merges and Zitadel bumps the dep past the merge SHA, `r.Data.Resource`
will be available on `AuthRequest` in the `/authorize` path, so T-014
can wire propagation directly — no sidecar needed. This adds a new
remediation option:

- **Option D (new)**: land the upstream PR first, bump the dep, then
  land T-014+T-026+T-027+T-045 in a single coherent PR that closes
  the F-001 window. T-004 stays as-is because the next-tier code path
  uses the accepted `resource` value. This is the cleanest outcome
  when the upstream merge has a short SLA.

Preferred path depends on upstream merge timeline. Short SLA →
Option D; long SLA → Option B (bundle T-004+T-026+T-027 in Tier 2
with the interim sidecar from T-012).
