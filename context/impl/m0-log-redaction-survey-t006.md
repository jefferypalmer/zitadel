---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# T-006 — M0 Log-Redaction Posture Survey

Build site: context/plans/build-site.md
Cavekit: cavekit-security-hardening.md R3 (log redaction)

## Posture: bodies are NOT logged today. Defensive wrappers still required.

### 1. HTTP middleware — `internal/api/http/middleware/log_interceptor.go`

`LogHandler(service string, ignoredPrefix ...string)` logs only:
`protocol`, `service`, `http_method`, `path`, `status`, `duration`.

No request or response body is serialized into the log record. No
header is logged. No query-string value is logged except as part of
`r.URL.Path` (which is path-only — `http.Request.URL.Path` does not
include the raw query string).

**Risk for DCR**: none under default configuration.

### 2. gRPC connect middleware — `internal/api/grpc/server/connect_middleware/log_interceptor.go`

`LogHandler(ignoredMethodSuffixes ...string)` logs only:
`protocol`, `service`, `http_method`, `path`, `code`, `duration`.

No request/response body, no message fields. `connect.AnyRequest` is
never marshaled.

**Risk for DCR IAT admin gRPC (T-023)**: none under default
configuration. `CreateInitialAccessTokenResponse.token` plaintext is
not logged.

### 3. Audit log — `internal/logstore/record/access.go`

`AccessLog` captures: `requestUrl`, `responseStatus`, `requestHeaders`,
`responseHeaders`, `requestedDomain`, `requestedHost`, `instanceId`,
`projectId`. Bodies are NOT captured.

Existing redaction (`Normalize()`):
- Request headers: `authorization`, `grpcgateway-authorization`,
  `cookie`, `grpcgateway-cookie` → `[REDACTED]`.
- Response headers: `set-cookie` → `[REDACTED]`.
- Header values truncated to 200 chars; max 10 values per key.
- Request URL truncated to 200 chars.

**Risk for DCR**:
- RATs arrive in the `Authorization: Bearer <rat>` header (RFC 7592
  §2.1). Already redacted.
- IATs arrive in `Authorization: Bearer <iat>` (RFC 7591 §3). Already
  redacted.
- `software_statement` is in the POST body. Body is not logged. ✓
- `client_secret` is returned in the POST response body. Body is not
  logged. ✓

**Gap**: DCR must NEVER put a token in a URL query string. All DCR
endpoints use Bearer-only auth — documented in `cavekit-register-handler.md`
R3 and `cavekit-manage-handler.md` R2. No change needed to
`access.go`, but T-061 should assert this invariant in its test.

## Outstanding work (inputs to T-061, T-062, T-063)

Cavekit R3 requires **defensive** redaction wrappers even when bodies
are not logged today, so a future `slog.DebugContext` addition doesn't
silently leak tokens. Concrete T-061 scope:

1. **DCR HTTP handler** (T-031/T-050 entry point): wrap the handler
   chain in a `redactingLogger` helper that strips `client_secret`,
   `registration_access_token`, `software_statement`, `token` (IAT
   plaintext), and Authorization from any `slog.Attr` set inside the
   DCR package. Applies to any future debug-level logging, not to
   current Info-level logging (which already logs only minimal fields).
2. **IAT admin gRPC handler** (T-023): same wrapper on the server-side
   response marshaling path — specifically ensure
   `CreateInitialAccessTokenResponse.token` is never copied into a
   `slog.Attr` value, and add a test asserting zero plaintext `zdiat_`
   substring in captured log output under `-v`/`--log-level=debug`.
3. **Audit log**: confirm no DCR-specific code path writes an AccessLog
   with a header name NOT in the existing redact set. Document the
   invariant in `cavekit-security-hardening.md` R3 so any future added
   header (e.g., `DPoP` — T-042 cache headers) goes through the same
   redaction.
4. **`internal/logstore/`** (T-063): grep-level audit — no code path in
   `internal/logstore/**` reads an IAT plaintext field or a request
   body; confirmed by this survey but the audit must be re-run by T-063
   against the merged DCR code.

## Test files listed by the cavekit (not part of T-006)

- `dcr_log_redaction_test.go` → T-062.
- `dcr_grpc_iat_logging_redaction_test.go` → T-062.

## R3 acceptance-criteria mapping (carryover to T-061/T-062/T-063)

- [x] M0 inspection of HTTP/gRPC log interceptors — this file.
- [ ] Redactor stripping client_secret, RAT, software_statement, Auth
      header, IAT token — deferred to T-061.
- [ ] Defensive wrappers at DCR HTTP handler + IAT gRPC handler —
      deferred to T-061.
- [ ] `internal/logstore/` IAT-leak audit — deferred to T-063.
- [ ] `dcr_log_redaction_test.go` / `dcr_grpc_iat_logging_redaction_test.go`
      integration tests — deferred to T-062.
