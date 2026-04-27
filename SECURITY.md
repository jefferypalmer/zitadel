# Security Policy

## Introduction

At ZITADEL we are extremely grateful for security aware people who disclose vulnerabilities to us and the open source community.
All reports will be investigated by our team, and we will work with you closely to validate and fix vulnerabilities reported to us.

We require that you keep vulnerabilities confidential until we are able to address them, since public disclosure of security vulnerabilities could put the ZITADEL community at risk.

## Scope

The scope of this policy applies to all security issues that concern our Product in form of Software in our [open source repositories](https://github.com/zitadel).

Out of scope are all websites and services operated by ZITADEL (CAOS Ltd.).
Please refer to the separate [vulnerability disclosure policy](https://zitadel.com/docs/legal/policies/vulnerability-disclosure-policy).

### Supported Versions

Supported are releases that are newer and not older than 6 months from our stable release. You can read more about the release cycle [here](https://zitadel.com/docs/product/release-cycle)

### Out of scope (what is NOT a security vulnerability)

- Disclosure of known public files or directories, e.g. robots.txt, files under .well-known, or files that are included in our public repositories (e.g. `go.mod`)
- DoS of users when [Lockout Policy is enabled](https://zitadel.com/docs/guides/manage/console/default-settings#lockout)
- You need help applying security related settings
- When messages sent by Zitadel are reprocessed by third-party clients that automatically change the content of the message.

## Reporting a vulnerability

To file an incident, please disclose it by e-mail to [security@zitadel.com](mailto:security@zitadel.com) including the following details of the vulnerability:

- Target: ZITADEL, Website (zitadel.com), ZITADEL Cloud (zitadel.cloud), Other (please describe)
- Type: For example DoS, authentication bypass, information disclosure, broken authorization, ...
- Description: Provide a detailed explanation of the issue, steps to reproduce, and assumptions you have made
- URL / Location (optional): The URL of the vulnerability
- Contact details (optional): In case we should contact you on a different channel

At the moment GPG encryption is no yet supported, however you may sign your message at will.

Your email will be acknowledged within 48 hours.
We will follow up within the next 3 business days indicating next steps in handling your report.

If you haven't received a response within 48 hours, or you didn't get a reply from our security team within the last 5 days, please contact [support@zitadel.com](mailto:support@zitadel.com).

Please inform us in your report whether we should mention your contribution.
We will not publish this information by default to protect your privacy.

## Threat Model — Dynamic Client Registration (DCR) Phase 1

OAuth 2.0 Dynamic Client Registration (RFC 7591 / 7592 / 8414) ships
disabled-by-default and is gated behind a per-instance feature flag
plus a YAML-level kill switch. The threat model below enumerates the
twenty residual concerns the implementation deliberately addresses.
Detailed mitigation evidence — source paths, test files, and
deferred-mitigation notes — lives in the engineering artifact at
`context/impl/m_t084_threat_model_evidence.md`.

| #   | Threat                                                 | Mitigation summary                                                                                                                              |
| --- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| T1  | Unauthenticated registration spam (anonymous mode)     | Inherited instance access quota + `MaxRequestBodyBytes` cap; IAT-required mode is the operator escape hatch.                                    |
| T2  | Phishing-grade `redirect_uri` registration             | Per-project isolation; consent flow; `AllowedRedirectURIHostPatterns` allow-list; audit log records source IP (SHA-256) + User-Agent.           |
| T3  | Public-client downgrade (`auth_method=none` no PKCE)   | Server enforces PKCE S256 when `auth_method=none`; `client_secret_jwt` rejected; `private_key_jwt` requires `jwks_uri`.                         |
| T4  | RAT leakage at rest or in transit                      | Plaintext emitted exactly once at registration / rotation; persisted as Passwap hash; rotated atomically on every PUT; silent rehash event.     |
| T5  | IAT replay beyond `max_uses`                           | Eventstore `UniqueConstraint` per slot at commit-time; 3-retry consume loop; admin revoke; expiry.                                              |
| T6  | `software_statement` algorithm confusion               | Feature off by default; statement supplied while disabled rejected with `unapproved_software_statement`.                                        |
| T7  | RFC 7592 manage-endpoint enumeration via 404           | Anti-enumeration dummy-Verify on unknown `client_id`; uniform 401 with `WWW-Authenticate`; `Cache-Control: no-store` on the 401.                |
| T8  | SSRF via `jwks_uri` fetch                              | Deny-list (RFC 1918, loopback, link-local, IPv6 ULA); DNS-rebind defense (single-resolve + pinned-IP dial); 3-hop redirect cap; 1 MiB body cap. |
| T9  | Stored XSS via `client_name` / `logo_uri`              | Untrusted display-only contract; console template-escapes; `logo_uri` is NOT auto-fetched.                                                      |
| T10 | Over-broad grant types via registration                | Server-side intersection with operator-configured allow-lists for grant / response / auth method / application type.                            |
| T11 | Cross-tenant escalation via IAT replay                 | IAT is bound to `{instance_id, org_id, project_id}`; cross-instance / cross-org abuse rejected with anti-enum dummy-Verify timing match.        |
| T12 | Timing side-channel — known vs unknown `client_id`     | Both branches run a real Passwap `Verify` (against stored hash or precomputed dummy); algorithm-mismatch panic at boot guards F-101 regression. |
| T13 | CSRF on DCR endpoints                                  | Existing CORS interceptor reused (no DCR-specific knob); never `Allow-Origin: *` together with `Allow-Credentials: true`.                       |
| T14 | Proxy / CDN secret caching of registration responses   | `Cache-Control: no-store` and `Pragma: no-cache` on every DCR response (POST 201, GET 200, PUT 200, 401 anti-enum).                             |
| T15 | Logs leak secrets                                      | Defensive `RedactSecrets` utility; HTTP + gRPC middleware do not log bodies; `internal/logstore/` audited; existing access-log Authorization redaction extended for IAT / RAT shapes. |
| T16 | Rotating-IP flood (botnet IP rotation bypassing per-IP rate-limits) | Operational-tier mitigation only — addressed via CDN / WAF and per-instance quotas; no DCR-specific test. Residual risk acknowledged in the architecture decision record (see ADR §T16). |
| T17 | Discovery emits `"registration_endpoint": null`        | `omitempty` JSON tag drops the key when the dual-gate is off; `as_metadata` mirrors the same field; both unit and integration tests pin the dual-state contract. |
| T18 | Projection lag on IAT consume                          | Eventstore-level `UniqueConstraint` is authoritative (commit-time, not projection-time); 3-retry loop re-fetches projection between attempts; Monte Carlo lag test asserts ≥95% retry success. |
| T19 | Eventstore flood from a registration burst             | Inherited instance access quota; `MaxRequestBodyBytes` cap. Burst signal surfaces via the `zitadel.dcr.errors_total` and `zitadel.dcr.request_duration_seconds` metrics. |
| T20 | Claude Code CLI changes registration payload shape     | Literal Claude Code MCP body is locked in `dcr_claude_code_compat_test.go` with an authorisation_code + PKCE S256 follow-up flow; quarterly CI re-run.    |

### XFF trust boundary

The DCR audit-log row stores `remote_addr_sha256` derived from
`internal/api/http.RemoteIPStringFromRequest`, which honours the
`X-Forwarded-For` first hop with a fallback to `r.RemoteAddr`.
ZITADEL deliberately does NOT parse `CF-Connecting-IP`, `X-Real-IP`,
or RFC 7239 `Forwarded` — operators that terminate TLS in front of
ZITADEL must rewrite those headers into `X-Forwarded-For` at the
ingress (or accept that the audit row records the load-balancer IP
hash). Misconfigured ingress ⇒ XFF spoofing, since DCR is reachable
without a per-request session.

### T16 product sign-off

The rotating-IP-flood residual risk for the anonymous-mode DCR
endpoint is acknowledged and product-signed-off in the ADR for
Dynamic Client Registration (`docs/adr/ADR-XXXX-dynamic-client-registration.md`).
Operators that disable IAT-required mode must front the endpoint
with a CDN or WAF capable of distributed-IP rate-limiting; the
ZITADEL access quota alone is per-instance and cannot defend
against a botnet that distributes one request per source IP.

## Disclosure Process

Our security team will follow the disclosure process:

1. We will acknowledge the receipt of your vulnerability report
2. Our security team will try to verify, reproduce, and determine the impact of your report
3. A member of our team will respond to either confirm or reject your report, including an explanation
4. Code will be audited to assess if the report uncovers similar issues
5. Fixes are prepared for the latest release
6. On the date that the fixes are applied, we will create a CVE and publish a [security advisory](https://github.com/zitadel/zitadel/security/advisories). Affected users of our Product, Services, or Website will be informed of the fix and required actions.

We think it is crucial to publish advisories `ASAP` as mitigations are ready. But due to the unknown nature of the disclosures the time frame can range from 7 to 90 days.
