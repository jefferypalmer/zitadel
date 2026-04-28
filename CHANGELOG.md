# Changelog

> **Source-of-truth note.** ZITADEL's authoritative version history lives
> in the [GitHub Releases page](https://github.com/zitadel/zitadel/releases),
> generated automatically by `semantic-release` from conventional commits
> on each tagged build. **This file is NOT in the `semantic-release`
> plugin chain** — it is hand-maintained as a curated narrative for
> cross-cutting features whose story does not fit a single commit
> message. If a release-tooling change later wires
> `@semantic-release/changelog` into `.releaserc.js`, this file becomes
> the auto-maintained log; until then, treat every entry below as a
> human-written supplement to the GitHub Release body.

## Unreleased

### OAuth 2.0 Dynamic Client Registration (RFC 7591 / 7592 / 8414 / 8707)

**Works with Claude Code out-of-the-box.** ZITADEL now ships OAuth 2.0
Dynamic Client Registration so that Claude Code, MCP Inspector, `mcp-remote`,
and any RFC 7591 client provisioner can register OIDC clients without
operator intervention.

The feature ships **disabled by default**; enable it by setting
`OIDC.DCR.Enabled: true` in the YAML configuration AND turning on the
`dynamic_client_registration` instance feature flag. See the
[Dynamic Client Registration API reference](apps/docs/content/apis/openidoauth/dynamic-client-registration.mdx),
[Claude Code (MCP) integration guide](apps/docs/content/guides/integrate/tools/claude-code-mcp.mdx),
[SECURITY.md threat model](SECURITY.md), and
[ADR-0001](docs/adr/ADR-0001-dynamic-client-registration.md).

**Key points operators must know:**

- **Hostname-root issuer required.** DCR is only supported on
  hostname-root issuers (`https://example.com/`), not subpath issuers
  (`https://example.com/zitadel/`). MCP clients including Claude Code
  resolve `registration_endpoint` against the issuer host. ZITADEL logs
  a structured warning the first time
  `/.well-known/oauth-authorization-server` is requested from a
  misconfigured subpath issuer (deduplicated per `(instance, issuer)`
  tuple thereafter), naming the probed URL; fix the deployment before
  exposing DCR to MCP-style consumers.
- **DELETE revokes tokens.** `DELETE /oidc/v1/register/{client_id}`
  returns 204 and revokes the client's outstanding access tokens AND
  refresh tokens on the same transaction (RFC 7592 §4 — the `RevokeApplicationTokens`
  command path). Operators who script management workflows around the
  manage endpoint should expect existing user sessions tied to the
  deleted client to terminate immediately.
- **Anonymous-by-default with hardening in place of authentication.**
  PKCE S256 enforcement on `auth_method=none`, redirect-URI clamping,
  body-size cap, instance-quota rate limiting, and per-registration
  audit events covering source-IP SHA-256 + User-Agent. For
  distributed-IP-flood defence (T16 in the threat model) operators
  must front the endpoint with a CDN or WAF — see
  [ADR-0001 §T16](docs/adr/ADR-0001-dynamic-client-registration.md) for
  the residual-risk product sign-off.
- **`registration_endpoint` is omitted, never null.** Both the OIDC
  discovery document and the new RFC 8414 OAuth 2.0 Authorization
  Server metadata document at
  `${ISSUER}/.well-known/oauth-authorization-server` drop the
  `registration_endpoint` key entirely when DCR is disabled. The
  shared field values across the two documents are byte-identical.
- **`PUT` rotates the RAT.** Every successful PUT on the manage
  endpoint mints a new Registration Access Token and invalidates the
  previous one atomically. The operation is **not idempotent** in the
  HTTP sense — provisioning systems must persist the freshly-issued
  RAT from the PUT 200 response BEFORE attempting any retry.

### OAuth 2.0 Resource Indicators (RFC 8707) — fully supported

ZITADEL now honors the
[`resource` parameter](apps/docs/content/apis/openidoauth/resource-indicators.mdx)
on every grant type that issues an access token: authorization code,
refresh token, client credentials, device code, token exchange (RFC
8693), and JWT bearer profile. The parameter populates the issued
token's `aud` (audience) claim, enabling per-API token scoping out of
the box.

**Migration note for existing token-exchange consumers.** Earlier
documentation said "ZITADEL does not yet support Resource Indicators.
Supplying this parameter will always result in a `invalid_target` error."
That is **no longer true** — `resource` is now accepted on token
exchange and is additive-merged with the legacy `audience` parameter
and the audience computed from `subject_token` / `actor_token`. The
narrowing rule (issued audience MUST be a subset of subject_token's
audience) still applies. Code that was relying on `invalid_target`
being an error sentinel for "feature not supported" needs updating.

**Operator allow-list.** Set
`OIDC.DCR.AllowedAudiences: [...]` in YAML to restrict the set of
resources clients may target. Empty (the default) means unrestricted.
The allow-list applies to every grant type, including refresh — a
refresh request asking for a resource that has since been removed from
the allow-list is rejected with `invalid_target`, so operators can
revoke audience access without rotating clients.

**Refresh narrowing.** Per RFC 8707 §2.2, a refresh request MAY narrow
the audience to a subset of the original grant. Asking for a resource
that wasn't authorized originally returns `invalid_target` 400.

**Library support.** The upstream Go library
[`github.com/zitadel/oidc/v3`](https://github.com/zitadel/oidc) gains a
`Resource []string` field on `oidc.AuthRequest` (mirroring the existing
`TokenExchangeRequest.Resource` pattern). See its UPGRADING.md for the
import-side change.

### Console: Dynamic Clients view + IAT admin

Two new console surfaces ship with DCR enabled:

- **Dynamic Clients view** — read-only listing of DCR-registered
  clients per project (sidenav peer alongside General / Roles / Project
  Grants / Grants on the project-detail page). Each row links to the
  application's audit timeline. Backed by a new
  `OIDCConfig.dynamically_registered` boolean field on the
  `App` proto, available to any management-API consumer that wants to
  filter their own listing.
- **Initial Access Tokens admin** — issue / list / revoke IATs from
  Instance Settings (sidenav peer to Security). The Issue dialog
  enforces a one-year lifetime cap, accepts the kit-pinned 6 fields
  (project_id, lifetime, max_uses, allowed_grant_types,
  allowed_redirect_uri_patterns, description), shows the plaintext
  token EXACTLY ONCE behind an explicit Reveal click, auto-masks after
  60 seconds, zeroes the in-memory reference on close, and refuses
  revoke on rows with empty `project_id`. The list paginates with
  default page size 100 (options 25/50/100/250).

See the [Console walkthrough](apps/docs/content/guides/manage/console/dynamic-client-registration.mdx)
for step-by-step instructions and the full field set.
