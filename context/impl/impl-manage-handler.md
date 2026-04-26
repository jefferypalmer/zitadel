---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-26T00:00:00Z"
---
# Implementation Tracking: RFC 7592 Management Handler

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-007 | DONE | M4 decision gate: DELETE token-revocation path (a) `RevokeApplicationTokens` SELECTED over path (b) docs-only. Artifact: `context/impl/m4-token-revocation-decision-t007.md`. Evidence: `RevokeOIDCSessionToken` (oidc_session.go:266) is per-token, no bulk equivalent; no `SessionsByClientID` query helper exists today; `RemoveApplication` (project_application.go:121) does not revoke tokens. Path (a) requires new query + command in T-056; primitives (`AccessTokenRevokedEvent`, `RefreshTokenRevokedEvent`, `oidc_session` projection with clientID) exist. Path (b) rejected — contradicts RFC 7592 §4 REQUIRES language. |
| T-032 | DONE | Shared `errors.go` + `validate.go` skeleton in `internal/api/oidc/dcr/`. errors.go exports ErrorEnvelope (RFC 7591 §3.2.2) + WriteError (sets `Content-Type: application/json;charset=UTF-8` + Cache-Control no-store + Pragma no-cache + envelope JSON) + RFC 7591 error-code constants (ErrCodeInvalidRedirectURI / ErrCodeInvalidClientMetadata / ErrCodeInvalidSoftwareStatement / ErrCodeUnapprovedSoftwareStatement / ErrCodeFeatureDisabled / ErrCodeInvalidToken / ErrCodeInvalidRequest / ErrCodeNotImplemented). zerrors-ID convention `DCR-<5 alphanumeric>` documented in trailing comment for T-033/T-034/T-036/T-040/T-054 to adopt. validate.go is doc-only skeleton announcing the public API (ValidateAndClampMetadata + ApplyDefaultsRFC7591 + CheckRedirectURIs) that T-033/T-034/T-054 will fill — keeping the file present reserves the import path. handler.go refactored to consume `WriteError` + `ErrCodeInvalidRequest` / `ErrCodeFeatureDisabled` / `ErrCodeNotImplemented`; existing 17 subtests still green (`go test ./internal/api/oidc/dcr/...` 0.008s). |
