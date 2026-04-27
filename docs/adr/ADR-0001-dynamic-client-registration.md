# ADR-0001: OAuth 2.0 Dynamic Client Registration (RFC 7591/7592/8414)

## Status

Accepted — 2026-04-27. Phase-1 implementation in progress; ships
disabled-by-default behind `OIDC.DCR.Enabled` plus the per-instance
feature flag `KeyDynamicClientRegistration`.

## Context

Claude Code, MCP Inspector, `mcp-remote`, and the broader MCP / agent
tooling ecosystem rely on OAuth 2.0 Dynamic Client Registration
(RFC 7591) to provision short-lived OIDC clients without operator
intervention. ZITADEL Phase-1 DCR exists primarily to unblock that
integration; it is also a prerequisite for compliance with RFC 7591
§2 and OIDC Registration 1.0 §2 for tenants that publish a
`registration_endpoint` in their discovery document.

The full architectural rationale, Spec-Surface conformance map, and
threat model live in:

- `context/refs/dcr-plan.md` — Phase-1 implementation plan (1440
  lines, 13 senior-review audit passes).
- `context/kits/cavekit-overview.md` — eight-domain kit decomposition.
- `context/impl/m_t084_threat_model_evidence.md` — T1–T20 evidence
  map; the public-facing summary is rendered into `SECURITY.md`.

This ADR captures only the architecture decisions where future
maintainers are most likely to challenge the call; it is not a
re-statement of the kits.

## Decisions

### D-1 Endpoint shape: HTTP + JSON, NOT gRPC

`POST /oidc/v1/register` and `GET|PUT|DELETE /oidc/v1/register/{client_id}`.
RFC 7591 specifies exact JSON body and error-envelope shapes that do
not round-trip cleanly through grpc-gateway's transcoding. The handler
lives at `internal/api/oidc/dcr/`, mounted via
`apis.RegisterHandlerOnPrefix` — colocated with `/oidc/v1/userinfo`
and `/oidc/v1/end_session` so existing OIDC TLS posture and CORS
middleware apply unchanged.

### D-2 Authentication model: anonymous-by-default + optional IAT

Phase-1 ships with anonymous registration as the default and the
RFC 7591 Initial Access Token (IAT) as an opt-in hardening. The
hardening applied **in place of** authentication on the anonymous
path is operator-tunable:

- per-instance access quota inherited from `limitingAccessInterceptor`,
- mandatory `redirect_uris` clamping through `domain.GetOIDCV1Compliance`
  plus an optional host-pattern allow-list,
- mandatory PKCE S256 when `token_endpoint_auth_method=none`,
- `MaxRequestBodyBytes` cap,
- defaults that produce a public client (`application_type=native`,
  `auth_method=none`, no secret issued),
- every successful registration is an audit event.

Tenants with stricter threat models flip
`OIDC.DCR.RequireInitialAccessToken=true` and mint IATs through the
new admin gRPC API. Claude Code cannot supply an IAT today, so this
mode is incompatible with Claude Code by design — tenants choosing
it accept that trade-off explicitly.

Rationale: an earlier draft of the plan defaulted to IAT-required.
That choice would have broken the primary user of this feature
(Claude Code / MCP) at first contact; the threat of "random internet
users creating clients" is dramatically lower than the threat of
"our flagship integration breaks on default settings." See `dcr-plan.md`
§2.3 for the full rationale.

### D-3 Resource hierarchy: reuse `project.application`

Dynamic clients are standard `Application`s under a `Project` under
an `Org`. No new aggregate. The default placement is a Phase-1
operator-configured `DCR.DefaultProjectID` / `DCR.DefaultOrgID`.
Per-org DCR policies are deferred to Phase 2.

### D-4 Event model: additive

Five new events on the `project` aggregate, all additive (older
consumers ignore them via `omitempty`):

- `project.application.dynamically.registered` — audit context
  carrying `{initial_access_token_id, software_statement_jti,
  registration_method, client_name_unclamped, remote_addr_sha256,
  user_agent}`.
- `project.application.registration_access_token.set` — Passwap-encoded RAT.
- `project.application.registration_access_token.rotated` — emitted on PUT.
- `project.application.registration_access_token.rehashed` — silent
  rehash on Passwap algorithm rotation.
- IAT lifecycle events (Added / Consumed / Revoked) scoped to the
  same project aggregate, with a `UniqueConstraint` per consumed
  slot for race-safe `max_uses` enforcement.

The audit event is the source of truth for the feature; the
projection at `internal/query/projection/app.go` is a read-side
optimization only.

### D-5 RAT rotation on every PUT

Stricter than RFC 7592's MAY. Every successful PUT mints a new RAT,
hashes it via Passwap, atomically pushes both the rotation event and
the OIDC config change event, and surfaces the plaintext exactly
once in the response body. Old RAT is immediately invalid (the
projection updates the hash column on the same transaction).

### D-6 Anti-enumeration on RFC 7592

Unknown `client_id` returns 401 with the same `WWW-Authenticate`
header and the same body shape as a known `client_id` with a wrong
RAT. Both branches run a real Passwap `Verify` — known-client uses
the stored hash, unknown-client uses a precomputed startup-time
dummy hash whose algorithm prefix matches the configured
`SecretHasher.Algorithm`. A boot-time probe panics on algorithm
mismatch (defence against the F-101 dummy-hash drift class).

### D-7 jwks_uri SSRF defence

Dedicated fetcher at `internal/api/oidc/dcr/jwks_fetcher.go` with:

- IP deny-list (RFC 1918, loopback, link-local, IPv6 ULA);
- DNS-rebind defence (single resolve + pinned-IP dial);
- 3-hop redirect cap with per-hop re-validation;
- 1 MiB body cap;
- configurable `HTTPTimeout`;
- dev-only `AllowLoopbackInDev` override.

### D-8 Discovery dual-state contract

`registration_endpoint` is JSON-tag `omitempty`. Disabled DCR drops
the key entirely; enabled DCR emits an absolute `https://` URL.
Discovery and RFC 8414 AS-metadata documents share a single source
struct so the values are byte-identical.

## Consequences

### Positive

- Claude Code / MCP integration works out of the box with default
  ZITADEL config plus `OIDC.DCR.Enabled=true`.
- RFC 7591 / 7592 / 8414 / 8707 conformance unblocks broader
  ecosystem adoption.
- Anonymous-by-default is reversible — operators can flip
  `RequireInitialAccessToken=true` without a redeploy or a data
  migration.
- Five new events are additive; existing replay tooling continues
  to work unchanged.

### Trade-offs

- Anonymous registration requires the operator to size
  `limitingAccessInterceptor` for the expected DCR write volume.
  Misconfiguration manifests as a 429 storm, not a security issue.
- The `private_key_jwt` path's `jwks_uri` SSRF defence pulls a
  cold-start network resolve into the registration request path —
  observed latency overhead is bounded by `HTTPTimeout` (default
  10s).
- Each successful registration burns five eventstore rows plus one
  RAT-set row — operators with very high registration churn need
  to size eventstore retention accordingly. The
  `zitadel.dcr.registrations_total` and
  `zitadel.dcr.request_duration_seconds` metrics surface this.

### Residual risks

#### T16 — Rotating-IP flood — PRODUCT SIGN-OFF

The anonymous-mode DCR endpoint is reachable without per-request
authentication. A botnet that distributes one registration per
source IP can defeat the per-IP rate-limiting components of any
load-balancer or CDN. ZITADEL's own access quota is per-instance,
not per-IP, and cannot defend against this distributed shape.

This residual risk is **acknowledged and signed off by Product**
for Phase-1 ship. The compensating controls are operational:

- Operators that need defence against distributed-IP floods MUST
  front the endpoint with a CDN or WAF capable of
  distributed-IP rate-limiting (Cloudflare Bot Management,
  Cloudflare Rate Limiting Rules, AWS WAF Bot Control, similar).
- Operators that cannot deploy such a layer SHOULD enable
  `OIDC.DCR.RequireInitialAccessToken=true` and accept the
  Claude Code incompatibility trade-off.
- The eventstore burst signal surfaces via
  `zitadel.dcr.errors_total{code=server_error}` and
  `zitadel.dcr.request_duration_seconds` p99 — operators MUST
  monitor these and tune quotas accordingly.

The full T1–T20 threat-model summary lives in `SECURITY.md`; the
engineering evidence map (source paths, test files, deferred-mitigation
notes) is at `context/impl/m_t084_threat_model_evidence.md`.

## Sign-off

| Role | Approved | Date |
|------|----------|------|
| Engineering | ✅ | 2026-04-27 |
| Security | ✅ | 2026-04-27 |
| Product (incl. T16 residual-risk acknowledgement) | ✅ | 2026-04-27 |

## References

- RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol.
- RFC 7592 — OAuth 2.0 Dynamic Client Registration Management
  Protocol.
- RFC 8414 — OAuth 2.0 Authorization Server Metadata.
- RFC 8707 — Resource Indicators for OAuth 2.0.
- RFC 8252 — OAuth 2.0 for Native Apps (loopback redirect-URI
  guidance).
- OpenID Connect Dynamic Client Registration 1.0.
- `context/refs/dcr-plan.md` — Phase-1 implementation plan.
- `context/kits/cavekit-overview.md` — eight-domain kit decomposition.
- `context/impl/m_t084_threat_model_evidence.md` — T1–T20 evidence map.
