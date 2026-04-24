---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# Implementation Tracking: RFC 7592 Management Handler

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-007 | DONE | M4 decision gate: DELETE token-revocation path (a) `RevokeApplicationTokens` SELECTED over path (b) docs-only. Artifact: `context/impl/m4-token-revocation-decision-t007.md`. Evidence: `RevokeOIDCSessionToken` (oidc_session.go:266) is per-token, no bulk equivalent; no `SessionsByClientID` query helper exists today; `RemoveApplication` (project_application.go:121) does not revoke tokens. Path (a) requires new query + command in T-056; primitives (`AccessTokenRevokedEvent`, `RefreshTokenRevokedEvent`, `oidc_session` projection with clientID) exist. Path (b) rejected — contradicts RFC 7592 §4 REQUIRES language. |
