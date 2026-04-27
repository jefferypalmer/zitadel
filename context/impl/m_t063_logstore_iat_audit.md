---
created: "2026-04-27T13:00:00Z"
last_edited: "2026-04-27T13:00:00Z"
---
# T-063 — `internal/logstore/` IAT-leak Audit

Build site: context/plans/build-site.md
Cavekit: cavekit-security-hardening.md R3 + R6 T15
Audit owner: DCR implementer (T-063)
Audit date: 2026-04-27

## Audit conclusion

**No IAT-leak surfaces in `internal/logstore/`.** The package's two
record types (`AccessLog`, `ExecutionLog`) carry NO request bodies and
already redact the only header channel through which an IAT or RAT
plaintext could enter (`Authorization` + the gRPC gateway counterpart
+ cookies).

## Methodology

1. `grep -rn "zdiat_\|InitialAccessToken\|initial_access_token\|iat_token\|iatToken\|IATToken\|Authorization\|Bearer\|client_secret\|registration_access_token" internal/logstore/`
   → only two matches, both in
   `internal/logstore/record/access.go` lines 58 + 86 (the existing
   redaction surface).
2. `grep -rn "Body\|body\|Payload" internal/logstore/record/`
   → zero matches. Bodies are not part of either record type's schema.
3. Reviewed both record types end-to-end:
   - `AccessLog` (`access.go:13-30`): RequestURL + Request/ResponseHeaders
     + InstanceID/ProjectID + RequestedDomain/RequestedHost +
     ResponseStatus. **No body field.**
   - `ExecutionLog` (`execution.go:9-17`): Took + Message + LogLevel +
     InstanceID + ActionID + Metadata. **Action-author-controlled** —
     IAT exposure here would be the action author echoing the token,
     mitigated upstream by the cavekit-security-hardening.md R3
     redaction-regex wrapper (T-061).

## Findings

### Existing redaction (sufficient)

`AccessLog.Normalize()` at `record/access.go:83-90` calls
`normalizeHeaders` with the exact list:
- `authorization`
- `grpcgateway-authorization`
- `cookie`
- `grpcgateway-cookie`

Plus response-side `set-cookie`. All redacted to literal `[REDACTED]`.

The IAT delivery contract (cavekit-register-handler.md R3) puts the
token on the Authorization header, so this redaction covers it. The
RFC 7592 RAT delivery contract (cavekit-manage-handler.md R2) uses the
same header — same redaction.

### Truncation

`RequestURL` is cut to 200 chars (`record/access.go:85`). IATs are NOT
delivered in URL paths or query strings (kit R3), so this is not a
relevant leak surface — but a malformed integration that DID place an
IAT in a URL would still risk leaking the prefix. Out of scope for
T-063; defence-in-depth for T-061's regex wrapper.

### Body channel

Neither `AccessLog` nor `ExecutionLog` carries a request body field.
The admin gRPC `CreateInitialAccessToken` response body returns the
plaintext IAT exactly once per RFC 7591 §3.2.1 contract — but
logstore has no path to record gRPC response bodies, so the plaintext
never enters this layer.

### ExecutionLog (action-runtime)

`ExecutionLog.Message` carries action-author code output. An action
author could deliberately or accidentally emit an IAT plaintext into
the log message. This is a USER-INPUT surface, not a Zitadel-emitted
secret leak — defence-in-depth via the cavekit-security-hardening.md
R3 amendment regex (`zdiat_[^\s"',]+` + `zdrat_[^\s"',]+`) at the
log-emitter layer (T-061 / T-062) is the correct mitigation.

## Regression test

New subtest in `internal/logstore/record/access_test.go` pinning
literal IAT-shaped (`zdiat_<id>.<random>`) and RAT-shaped (`zdrat_...`)
Bearer values are redacted by `AccessLog.Normalize`. A future change
that disables redaction or removes Authorization from the redact list
fails these subtests in addition to the generic "AValue" baseline.

## Cross-references

- T-006 — M0 log-redaction posture survey
  (`context/impl/m0-log-redaction-survey-t006.md`) — broader audit of
  HTTP + gRPC + audit-log middleware bodies.
- T-061 (Tier 5) — log-redaction wrappers stripping client_secret +
  RAT + software_statement + Authorization + IAT-token field at the
  emitter layer. **T-063 audit shows the wrapper is needed for the
  ExecutionLog action-author surface, NOT for AccessLog (already
  covered).**
- T-062 — log-redaction integration tests (downstream).
- cavekit-security-hardening.md R3 amendment 2026-04-27 — full-token
  log-redaction regex.
- cavekit-security-hardening.md R6 T15 — logs-leak-secrets threat.

## Status

R3 audit ✓ — no leak surface in `internal/logstore/` beyond the
already-redacted Authorization channel; ExecutionLog action-runtime
surface explicitly out of scope (T-061 wrapper covers).
R6 T15 — partially covered by this audit; full coverage when T-061 +
T-062 land.
