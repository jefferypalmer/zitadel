---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
complexity: medium
---

# Cavekit: OIDC Discovery + RFC 8414 AS Metadata

## Scope
Defines the two well-known endpoints that advertise DCR to clients: (a) the existing OIDC discovery document at `/.well-known/openid-configuration` gains the `registration_endpoint` field; (b) a NEW RFC 8414 OAuth Authorization Server metadata handler at `/.well-known/oauth-authorization-server` is added. Both documents MUST agree on endpoint values. The new path MUST be registered in the public-prefix list so middleware exposes it.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §1.3, §1.4, §15.10 (hostname-root requirement), §17.1 (oidc/v3 field), §4.2 (server.go + start.go edits)
- Spec references: RFC 8414 §2, OIDC Discovery 1.0, RFC 7591 §3 (`registration_endpoint`)

## Requirements

### R1: OIDC discovery `registration_endpoint` advertisement
**Description:** The existing OIDC discovery handler must populate `RegistrationEndpoint` in `createDiscoveryConfig` when the dual-gate from `cavekit-config.md` R3 is satisfied. The library field already exists at the pinned version; `omitempty` ensures the key is dropped (NOT emitted as `null`) when DCR is disabled.

**Acceptance Criteria:**
- [ ] `internal/api/oidc/server.go` `createDiscoveryConfig` sets `RegistrationEndpoint` to `{issuer}/oidc/v1/register` when DCR is enabled.
- [ ] When DCR is disabled, the field is left zero-value so the `json:"registration_endpoint,omitempty"` tag drops the key from the JSON body.
- [ ] The discovery JSON body NEVER contains `"registration_endpoint": null` — only an absolute URL string or absence (Claude Code Zod parser bug GH #38102 reference).
- [ ] The issuer used for the URL is sourced from the same context-derived issuer the rest of `createDiscoveryConfig` uses (no hard-coded host).
- [ ] No upstream `oidc/v3` patch is needed — `RegistrationEndpoint string \`json:"registration_endpoint,omitempty"\`` exists in `github.com/zitadel/oidc/v3 v3.47.0` `pkg/oidc/discovery.go`.

**Dependencies:** `cavekit-config.md` R1, R3.

### R2: RFC 8414 AS metadata handler at `/.well-known/oauth-authorization-server`
**Description:** A new handler serves the RFC 8414 §2 fields as JSON. It is colocated under `internal/api/oidc/as_metadata/` (NOT `internal/api/oauth/`, which does not exist). The new path MUST be added to `cmd/start/start.go:446` `oidcPrefixes` so it is publicly reachable.

**Acceptance Criteria:**
- [ ] `internal/api/oidc/as_metadata/handler.go` exposes a `NewHandler(deps) http.Handler` constructor.
- [ ] The handler returns JSON with the RFC 8414 §2 required fields: `issuer`, `authorization_endpoint`, `token_endpoint` (conditional), `response_types_supported`.
- [ ] The handler also returns the recommended-for-DCR/MCP fields: `registration_endpoint`, `code_challenge_methods_supported: ["S256"]`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `scopes_supported`, `jwks_uri`.
- [ ] The path `/.well-known/oauth-authorization-server` is appended to the `oidcPrefixes` slice at `cmd/start/start.go:446` and is registered via the same `apis.RegisterHandlerPrefixes(...)` call as the rest of the OIDC public surface.
- [ ] When `OIDC.DCR.Enabled=false`, `curl http://localhost:8080/.well-known/oauth-authorization-server` returns 404 (handler unmounted).
- [ ] When `OIDC.DCR.Enabled=true`, the same `curl` returns 200 with a JSON body containing the fields above.

**Dependencies:** `cavekit-config.md` R1, R3.

### R3: Both documents agree
**Description:** OIDC discovery and RFC 8414 metadata MUST share the same source of endpoint values. Divergence (e.g., one references `https://x/oidc/v1/register` and the other `https://x/register`) breaks Claude Code MCP probing.

**Acceptance Criteria:**
- [ ] Endpoint values for `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, and `registration_endpoint` are produced by the same struct-assembly path (or compared by the same code) so the two handlers cannot diverge.
- [ ] An integration test (`dcr_discovery_test.go` and `dcr_as_metadata_test.go`) asserts byte-identical values for shared fields when DCR is enabled.
- [ ] When DCR is disabled, BOTH documents omit `registration_endpoint` (key absent from JSON, never `null`).

**Dependencies:** R1, R2.

### R4: Hostname-root deployment requirement
**Description:** RFC 8414 / Claude Code probing assumes Zitadel is deployed at hostname root. Subpath deployments are tolerated (no startup hard-fail) but a runtime WARN is emitted from the AS metadata handler (R2) when it observes a non-root issuer; documentation makes the requirement explicit.

The runtime check sits in the AS metadata handler (NOT at startup) because Zitadel's `ExternalDomain` is a hostname, not a URL — proxy-driven subpath deployments are NOT observable from startup config alone. The handler in R2 has access to the per-request issuer via `op.IssuerFromContext(ctx)` / `http_util.DomainContext(ctx).Origin()` and is the natural detection point.

**Acceptance Criteria:**
- [ ] The DCR documentation page and the deployment guide carry an explicit note: "DCR / MCP support requires Zitadel deployed at a hostname root (no URL subpath)."
- [ ] CHANGELOG entry mentions the hostname-root requirement.
- [ ] Startup behavior for explicitly-misconfigured `ExternalDomain` (a literal `/` in the value) is governed by `cavekit-config.md` R5 (WARN at startup; already implemented by T-010).
- [ ] T-030 AS metadata handler emits a WARN log on its first observation of a non-root issuer per instance (log-once cache keyed by `instanceID + issuer`). The log line names the hostname-root probe URL (`{scheme}://{host}/.well-known/oauth-authorization-server`) Claude Code will use.
- [ ] When the request issuer is at hostname root, NO warning is emitted.
- [ ] The handler still serves a 200 with metadata reflecting the non-root issuer (the warning is observational, not blocking).

**Dependencies:** R2; `cavekit-config.md` R5; `cavekit-console-ui-docs-and-observability.md` R3.

## Out of Scope
- RFC 9728 (`/.well-known/oauth-protected-resource`).
- Per-org discovery overrides.
- WebFinger.
- Discovery caching beyond Zitadel's existing HTTP-cache headers.

## Cross-References
- See `cavekit-config.md` R3, R5: dual-gate and issuer-path warning.
- See `cavekit-register-handler.md` R7: `registration_client_uri` construction shares the issuer source from R1.
- See `cavekit-console-ui-docs-and-observability.md` R3: hostname-root note in deployment docs.

## Source Traceability (brownfield)
- `internal/api/oidc/server.go` `createDiscoveryConfig` — existing function. [GAP] does not currently set `RegistrationEndpoint`.
- `github.com/zitadel/oidc/v3 v3.47.0` `pkg/oidc/discovery.go` `RegistrationEndpoint string \`json:"registration_endpoint,omitempty"\`` — [VERIFIED] exists in `go.mod` pin; referenced by `internal/api/oidc/server_test.go:74`.
- `cmd/start/start.go:446` — `oidcPrefixes` slice. [GAP] does not include `/.well-known/oauth-authorization-server`.
- `internal/api/oidc/as_metadata/` — [GAP] directory does not exist; must be created.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
