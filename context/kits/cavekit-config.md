---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
complexity: medium
---

# Cavekit: DCR Configuration & Feature Flag

## Scope
Defines the `OIDC.DCR.*` configuration tree shipped in `cmd/defaults.yaml`, the runtime feature flag (`KeyDynamicClientRegistration = 17`) added to `internal/feature/feature.go`, the dual-gate precedence between yaml `Enabled` and the runtime feature, startup validation behavior (including issuer-path warning), and rollback semantics when DCR is disabled after use. This is the root domain — every other DCR kit consumes config values defined here.

## Source
- Staged plan: `context/refs/dcr-plan.md`
- Authoritative sections: §6, §15.1, §15.10, §4.2 (feature.go row), §13.2 M0
- Spec references: RFC 7591 §3, RFC 7592 §3 (RAT lifetime), RFC 8707 §2 (resource allow-list)

## Requirements

### R1: `OIDC.DCR` config block in `cmd/defaults.yaml`
**Description:** A new `OIDC.DCR` block must be present in `cmd/defaults.yaml` declaring all DCR runtime knobs with the documented defaults. The block is opt-in: `Enabled: false`.

**Acceptance Criteria:**
- [ ] `cmd/defaults.yaml` contains a `DCR:` key under the existing `OIDC:` block.
- [ ] `Enabled` defaults to `false`.
- [ ] `RequireInitialAccessToken` defaults to `false` (anonymous-mode-by-default for Claude Code).
- [ ] `DefaultProjectID` and `DefaultOrgID` are present with empty-string defaults.
- [ ] `MaxRedirectURIs: 10` and `MaxRequestBodyBytes: 65536` present.
- [ ] `AllowedGrantTypes` defaults to `[authorization_code, refresh_token]` and OMITS `client_credentials` (admin opt-in only).
- [ ] `AllowedResponseTypes` defaults to `[code]`.
- [ ] `AllowedAuthMethods` defaults to `[none, client_secret_basic, client_secret_post, private_key_jwt]` (`none` REQUIRED for Claude Code; `client_secret_jwt` excluded).
- [ ] `AllowedApplicationTypes` defaults to `[native, web]`.
- [ ] `AllowedRedirectURIHostPatterns` defaults to `[]`.
- [ ] `AllowedAudiences` defaults to `[]` with comment documenting the empty-list-means-unrestricted sentinel rule (inverted from Go convention).
- [ ] `RegistrationAccessToken.Enabled: true` and `RegistrationAccessToken.Lifetime: 0s` (0 = no expiry per RFC 7592 §3 MAY).
- [ ] `InitialAccessToken.DefaultLifetime: 24h` and `InitialAccessToken.DefaultMaxUses: 1`.
- [ ] `SoftwareStatement.Enabled: false` and `SoftwareStatement.TrustedIssuers: []`.
- [ ] `ClientSecretExpiresIn: 0s` (0 = no expiry per RFC 7591 §3.2.1 `client_secret_expires_at: 0`).
- [ ] `JwksURI.HTTPTimeout: 10s`, `JwksURI.AllowLoopbackInDev: false`, and `JwksURI.DisallowedIPRanges` includes the documented set (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`).
- [ ] No `DCR.CORS` config tree exists — CORS is reused from `internal/api/http/middleware/cors_interceptor.go`.

**Dependencies:** none

### R2: Feature flag `KeyDynamicClientRegistration = 17`
**Description:** A new feature key must be added at value `17` (next free slot after `KeyEnableRelationalTables = 16`) and a matching `DynamicClientRegistration` boolean field added to the `Features` struct in `internal/feature/feature.go`. The field carries a snake_case JSON tag matching existing convention.

**Acceptance Criteria:**
- [ ] `internal/feature/feature.go` defines `KeyDynamicClientRegistration Key = 17` (or next available if 17 is taken).
- [ ] The `Features` struct has field `DynamicClientRegistration bool` with tag `` `json:"dynamic_client_registration,omitempty"` ``.
- [ ] M0 collision-check via `grep -n 'Key = 17\|Key=17' internal/feature/feature.go` confirms 17 is free; if not, the next available integer is used.
- [ ] No existing feature key value or struct field is renamed by this change.

**Dependencies:** none

### R3: Dual-gate precedence (yaml + runtime feature)
**Description:** DCR activation requires BOTH the yaml `OIDC.DCR.Enabled=true` AND the runtime feature flag `DynamicClientRegistration=true`. The yaml gate is decided at startup (controls handler mount); the runtime feature gate is decided per request.

**Acceptance Criteria:**
- [ ] When `OIDC.DCR.Enabled=false` at startup, the `/oidc/v1/register` handler is NOT mounted; requests to that path return 404 with no DCR-specific body.
- [ ] When `OIDC.DCR.Enabled=true` AND runtime feature flag is OFF for the instance, requests to `/oidc/v1/register` return HTTP 403 with the RFC 7591 error body shape `{"error":"feature_disabled","error_description":"..."}`.
- [ ] When BOTH gates are ON, the handler responds 2xx for valid requests.
- [ ] Feature-flag cache TTL inherits from Zitadel's existing feature-flag service (no DCR-specific cache).
- [ ] `/.well-known/oauth-authorization-server` registration handler advertisement obeys the same dual-gate (advertisement absent when either gate is off).

**Dependencies:** R1, R2

### R4: Startup validation
**Description:** When `Enabled=true` and `RequireInitialAccessToken=false`, the process MUST refuse to start if `DefaultProjectID` or `DefaultOrgID` is empty. Failures exit non-zero with a clear log message — never serve HTTP 503 from a partially-initialized handler.

**Acceptance Criteria:**
- [ ] Starting Zitadel with `OIDC.DCR.Enabled=true`, `RequireInitialAccessToken=false`, and empty `DefaultProjectID` produces a non-zero exit and a log line naming the missing key.
- [ ] Same for empty `DefaultOrgID`.
- [ ] Starting with `Enabled=false` succeeds regardless of `DefaultProjectID`/`DefaultOrgID` values.
- [ ] Starting with `Enabled=true` AND `RequireInitialAccessToken=true` succeeds even with empty `DefaultProjectID`/`DefaultOrgID` (IAT carries those identifiers).

**Dependencies:** R1

### R5: Issuer-path startup warning
**Description:** When DCR is enabled and the effective issuer URL has a non-empty path component, startup MUST log a WARN line naming the specific `.well-known` URL Claude Code will probe. Startup does NOT hard-fail (would break non-DCR users on subpath deployments).

**Acceptance Criteria:**
- [ ] Starting with `Enabled=true` and an issuer like `https://example.com/zitadel` emits a WARN log naming `https://example.com/.well-known/oauth-authorization-server` as the URL Claude Code will probe.
- [ ] Starting with `Enabled=true` and an issuer at hostname root emits no such warning.
- [ ] Starting with `Enabled=false` emits no such warning regardless of issuer path.
- [ ] The warning text references the deployment-guide doc section (hostname-root requirement, §15.10 / §17.4 of the staged plan).

**Dependencies:** R1

### R6: Rollback / disable behavior
**Description:** Flipping `Enabled=true` → `Enabled=false` after DCR-registered clients exist must leave existing clients fully usable for normal OIDC flows. Schema and projection columns are additive and never require rollback DDL.

**Acceptance Criteria:**
- [ ] After a flip to `Enabled=false`, requests to `/oidc/v1/register{/*}` return 404.
- [ ] DCR-created apps in `apps7_oidc_configs` continue to authorize/issue tokens via `/oauth/v2/authorize` and `/oauth/v2/token`.
- [ ] Existing RATs become unusable for self-service management (RFC 7592 endpoints unmounted) but admins can still delete the underlying app via the management API.
- [ ] Re-enabling DCR (`Enabled=true`) restores `/oidc/v1/register{/*}` and existing data is intact (no migration needed).
- [ ] Active IATs become unusable for `/oidc/v1/register` while disabled; admin gRPC IAT operations remain reachable subject to the runtime feature flag.
- [ ] All schema columns added by §7 of the plan are nullable (no rollback DDL required).

**Dependencies:** R1, R3

### R7: Integration-test fixture defaults
**Description:** Integration tests must default to DCR-enabled. `internal/integration/config/client.yaml` must contain `OIDC.DCR.Enabled: true` along with `DefaultProjectID` / `DefaultOrgID` resolved against the integration fixture.

**Acceptance Criteria:**
- [ ] `internal/integration/config/client.yaml` sets `OIDC.DCR.Enabled: true`.
- [ ] `DefaultProjectID` and `DefaultOrgID` reference the fixture instance's default org (resolvable via `internal/integration/oidc.go` / `Instance.DefaultOrganizationID()`).
- [ ] `go test -run=TestInstance_BasicLoadsConfig -tags integration` passes against the configured fixture.

**Dependencies:** R1, R4

## Out of Scope
- Per-org overrides (`OrgDCRPolicy` aggregate) — Phase 2.
- `software_statement` trusted-issuer verification — Phase 2 (config stub only in Phase 1).
- Inline `jwks` (vs `jwks_uri`) — Phase 2.
- `client_credentials` in default `AllowedGrantTypes` — admin opt-in only.
- Flipping `DCR.Enabled` default to `true` — deferred to a future major version.
- `client_name#<lang>` localized names.

## Cross-References
- See `cavekit-iat.md` R1: IAT events are gated by this feature flag at the gRPC layer.
- See `cavekit-register-handler.md` R1: handler mount obeys R3 dual-gate.
- See `cavekit-manage-handler.md` R1: same dual-gate applies.
- See `cavekit-discovery-and-as-metadata.md` R1, R2: `registration_endpoint` advertisement obeys R3.
- See `cavekit-rfc8707-resource.md` R3: `AllowedAudiences` config defined here drives RFC 8707 validation.
- See `cavekit-security-hardening.md` R2: `JwksURI.DisallowedIPRanges` defined here drives the SSRF guard.
- See `cavekit-console-ui-docs-and-observability.md` R6: deployment-guide hostname-root note is referenced by R5 warning.

## Source Traceability (brownfield)
- `cmd/defaults.yaml:638` — existing `OIDC:` block where the new `DCR:` subtree must be added. [GAP] subtree absent.
- `internal/feature/feature.go` — existing `Key` enum; `KeyEnableRelationalTables = 16` is highest. [GAP] no key 17 yet.
- `cmd/start/start.go:446` — existing `oidcPrefixes` slice; the path `/oidc/v1/register` is covered by `/oidc/v1` but `/.well-known/oauth-authorization-server` is NOT in the slice. [GAP] AS metadata prefix missing.
- `internal/integration/config/client.yaml` — integration test config; [GAP] no DCR keys present.
- `internal/integration/oidc.go` — `Instance.DefaultOrganizationID()` accessor [VERIFIED] exists for resolving fixture IDs.

## Changelog
- 2026-04-24: Initial draft from `dcr-plan.md`.
