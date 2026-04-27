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
