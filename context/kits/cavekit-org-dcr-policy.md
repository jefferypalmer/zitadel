---
created: "2026-04-28T00:00:00Z"
last_edited: "2026-04-28T00:00:00Z"
complexity: unknown
---

# Cavekit: Per-Org DCR Policy

## Scope
Defines a new `OrgDCRPolicy` aggregate that lets each organization narrow two instance-level DCR knobs: `AllowedAudiences` (set-narrowing only — must be a subset of the instance allow-list) and `RegistrationAccessTokenLifetime` (cap-narrowing only — must be ≤ the instance default). Mirrors Zitadel's existing dual-tier policy pattern (e.g., `domainPolicyProjection`, `passwordComplexityProjection`): shared event structs, separate aggregate wrappers for `org` and `instance`, a single projection table with an `is_default` boolean discriminating instance defaults (TRUE) from org overrides (FALSE), and a query helper that merges the two tiers via COALESCE-by-`is_default`. Effective policy resolution is request-time: org → instance → static `OIDC.DCR.*` config from `cavekit-config.md`. Provides the gRPC surfaces on `ManagementService` (org-scoped) and `AdminService` (instance-default) and emits the audit + observability surface required for production.

## Source
- Phase 2 design (Approach A) — user-approved.
- Phase 1 carve-outs: `cavekit-config.md` Out of Scope ("per-org overrides"); `cavekit-rfc8707-resource.md` Out of Scope ("per-org `AllowedAudiences` overrides"); `cavekit-manage-handler.md` Out of Scope ("per-org RAT lifetime overrides").
- Brownfield reference patterns: `internal/repository/policy/policy_domain.go` (shared event struct), `internal/repository/org/policy_domain.go` and `internal/repository/instance/policy_domain.go` (dual aggregate wrappers), `internal/query/projection/domain_policy.go` and `internal/query/projection/password_complexity_policy.go` (`is_default` projection columns).
- Spec references: RFC 7591 §2 (client metadata), RFC 7592 §3 (RAT lifetime), RFC 8707 §2 (`resource` allow-list).

## Requirements

### R1: `OrgDCRPolicy` aggregate, shared events, and commands
**Description:** A new policy is added to the eventstore using the established dual-tier pattern. Shared event structs live in the `policy` repository package; aggregate-specific wrappers live in `org` and `instance` packages. Commands expose org-scoped Set / Update / Reset / Remove operations and instance-scoped Set / Update operations.

**Acceptance Criteria:**
- [ ] A new shared event file `internal/repository/policy/policy_dcr.go` defines `DCRPolicyAddedEvent`, `DCRPolicyChangedEvent`, and `DCRPolicyRemovedEvent` (mirroring `policy_domain.go`).
- [ ] An org-aggregate wrapper file `internal/repository/org/policy_dcr.go` defines `OrgDCRPolicyAddedEvent` / `OrgDCRPolicyChangedEvent` / `OrgDCRPolicyRemovedEvent` carrying wire-type strings under the `org.policy.dcr.*` namespace (`org.policy.dcr.added`, `org.policy.dcr.changed`, `org.policy.dcr.removed`).
- [ ] An instance-aggregate wrapper file `internal/repository/instance/policy_dcr.go` defines `InstanceDCRPolicyAddedEvent` / `InstanceDCRPolicyChangedEvent` carrying wire-type strings under the `instance.policy.dcr.*` namespace.
- [ ] Org-scope command surface exposes `SetOrgDCRPolicy`, `UpdateOrgDCRPolicy`, `ResetOrgDCRPolicy` (back to instance default), and `RemoveOrgDCRPolicy`.
- [ ] Instance-scope command surface exposes `SetInstanceDCRPolicy` and `UpdateInstanceDCRPolicy` (instance default — no Reset/Remove because the instance default ALWAYS exists, falling through to static `OIDC.DCR.*` config when no event has been emitted).
- [ ] Event payloads carry exactly the fields `{allowed_audiences []string, registration_access_token_lifetime time.Duration}`; absent / null fields encode "inherit upper tier".

**Dependencies:** `cavekit-config.md` R1 (static-config fallback values).

### R2: `dcr_policies` projection table
**Description:** A single projection table — `projections.dcr_policies1` — holds both org overrides and instance defaults discriminated by an `is_default` boolean. Reducers handle the org Added/Changed/Removed events, the instance Added/Changed events, and `OrgRemoved` / `InstanceRemoved` cleanup.

**Acceptance Criteria:**
- [ ] The projection table is registered in `internal/query/projection/projection.go` and lives under the canonical name `projections.dcr_policies1`.
- [ ] Schema columns: `id TEXT NOT NULL`, `creation_date TIMESTAMPTZ NOT NULL`, `change_date TIMESTAMPTZ NOT NULL`, `sequence BIGINT NOT NULL`, `state SMALLINT NOT NULL`, `is_default BOOLEAN NOT NULL`, `allowed_audiences TEXT[] NULL`, `registration_access_token_lifetime BIGINT NULL` (interval encoded as nanoseconds for projection-tool portability), `resource_owner TEXT NOT NULL`, `instance_id TEXT NOT NULL`, `owner_removed BOOLEAN NOT NULL DEFAULT FALSE`.
- [ ] Primary key is `(instance_id, id)`.
- [ ] Reducers cover `OrgDCRPolicyAddedEvent` (INSERT with `is_default=FALSE`), `OrgDCRPolicyChangedEvent` (UPDATE), `OrgDCRPolicyRemovedEvent` (DELETE), `OrgRemovedEvent` (cascading set `owner_removed=TRUE`), `InstanceDCRPolicyAddedEvent` (INSERT with `is_default=TRUE`), `InstanceDCRPolicyChangedEvent` (UPDATE), and `InstanceRemovedEvent` (DELETE).
- [ ] An index `(instance_id, resource_owner)` exists to support the org-lookup case path of R3.
- [ ] `is_default=TRUE` rows have `resource_owner = instance_id` by convention; `is_default=FALSE` rows have `resource_owner = <org_id>`.

**Dependencies:** R1.

### R3: Effective-policy query helper
**Description:** A typed query helper resolves the effective DCR policy for a given `(instance_id, org_id)` pair by merging the org row (when present) over the instance row (when present) over the static `OIDC.DCR.*` config defaults — in a single SQL statement using COALESCE-by-`is_default` semantics so callers receive exactly one merged row.

**Acceptance Criteria:**
- [ ] A new file `internal/query/dcr_policy.go` exposes `DCRPolicyByOrg(ctx, instanceID, orgID) (*DCRPolicy, error)` returning the merged effective policy.
- [ ] When an org row exists, its non-NULL field values take precedence; NULL fields fall through to the instance default; if the instance default is also absent, the value is sourced from `OIDC.DCR.AllowedAudiences` and `OIDC.DCR.RegistrationAccessToken.Lifetime` from `cavekit-config.md` R1.
- [ ] The SQL is a single statement (embedded via `//go:embed dcr_policy_by_org.sql` next to the Go file) — no per-row second query.
- [ ] The returned `*DCRPolicy` struct exposes `AllowedAudiences []string`, `RegistrationAccessTokenLifetime time.Duration`, and a `Scope` field reporting whether the resolution drew from `org` / `instance` / `static-config` for each merged field (used by R7 for OTel attribute population).
- [ ] Cross-instance lookups (an `org_id` belonging to a different `instance_id`) return the instance-default-only path for the calling instance — no cross-instance leak.
- [ ] When neither an org row nor an instance row exists, the helper synthesizes the static-config-default policy without erroring.

**Dependencies:** R2; `cavekit-config.md` R1.

### R4: `AllowedAudiences` set-narrowing only
**Description:** An org-scoped `AllowedAudiences` value MUST be a subset of the effective instance allow-list. The empty list at org level encodes "inherit instance" (NOT "unrestricted"); the empty-list-as-unrestricted sentinel applies only at instance / static-config level per `cavekit-rfc8707-resource.md` R3. Out-of-bounds values are refused at the command boundary (Set / Update) before any event is emitted.

**Acceptance Criteria:**
- [ ] `SetOrgDCRPolicy` and `UpdateOrgDCRPolicy` reject any `AllowedAudiences` entry not present in the effective instance allow-list with command-layer error mapped to gRPC `INVALID_ARGUMENT` (HTTP-bridge → 400) and i18n key `Errors.DCR.OrgPolicy.InvalidAudienceSubset`.
- [ ] The error message names the FIRST violating URI in `error_description` (and only that one — never the full list, to bound log volume on adversarial input).
- [ ] When the effective instance allow-list is empty (unrestricted), org `AllowedAudiences` MAY be any syntactically valid URI list; the subset check is vacuously satisfied.
- [ ] An empty / unset org `AllowedAudiences` value is stored as NULL and resolved by R3 to "inherit instance" (NOT "no audiences allowed").
- [ ] When an instance admin SHRINKS the instance allow-list such that an existing org override is no longer a subset, existing org rows are NOT auto-mutated; subsequent `UpdateOrgDCRPolicy` calls on that org will fail R4 until the override is brought back into bounds. The eventstore reflects historical truth; the projection reflects current truth.
- [ ] Each `AllowedAudiences` entry is validated as a syntactically valid URI by the same parser used in `cavekit-rfc8707-resource.md` R3 (no divergence between Phase 1 RFC 8707 validation and Phase 2 policy validation).

**Dependencies:** R1, R3; `cavekit-rfc8707-resource.md` R3.

### R5: `RegistrationAccessTokenLifetime` cap-narrowing only
**Description:** An org-scoped `RegistrationAccessTokenLifetime` MUST be a positive duration AND ≤ the effective instance default. The `0s` sentinel ("no expiry" per RFC 7592 §3) is permitted at org level ONLY when the instance default is also `0s`; otherwise `0s` at org level is a violation (an org cannot be MORE permissive than the instance).

**Acceptance Criteria:**
- [ ] `SetOrgDCRPolicy` and `UpdateOrgDCRPolicy` reject any `RegistrationAccessTokenLifetime` strictly greater than the effective instance default with `INVALID_ARGUMENT` and i18n key `Errors.DCR.OrgPolicy.InvalidLifetimeCap`.
- [ ] Negative durations are refused with the same error key (mirrors the `cavekit-config.md` R1 ClientSecretExpiresIn refusal pattern — a negative lifetime would advertise expired-on-issue tokens).
- [ ] `0s` is permitted at org level if and only if the effective instance default is `0s`; any other combination of `0s` / positive at org versus positive / `0s` at instance is a violation.
- [ ] An empty / unset org lifetime is stored as NULL and resolved by R3 to the instance default.
- [ ] The cap check uses the EFFECTIVE instance default at the moment the command runs (not a cached value), so a runtime change to the instance default is observed by subsequent org commands.
- [ ] When an instance admin TIGHTENS the instance default such that an existing org override is now over-cap, existing org rows are NOT auto-mutated; subsequent `UpdateOrgDCRPolicy` on that org fails R5 until brought back into bounds. Historical truth preserved per R4 acceptance criterion.

**Dependencies:** R1, R3.

### R6: gRPC surfaces on `ManagementService` and `AdminService`
**Description:** Org-scoped operations live on `ManagementService` (read scoped to the caller's authenticated org); instance-default operations live on `AdminService`. Authentication metadata follows the prevailing pattern for `domain` / `password` policies in the existing proto.

**Acceptance Criteria:**
- [ ] `proto/zitadel/management.proto` `ManagementService` gains `GetOrgDCRPolicy`, `UpdateOrgDCRPolicy`, and `ResetOrgDCRPolicy` RPCs with HTTP and OpenAPI annotations matching the existing org-policy pattern (e.g., `GetDomainPolicy`, `UpdateCustomDomainPolicy`, `ResetDomainPolicyToDefault`).
- [ ] `proto/zitadel/admin.proto` `AdminService` gains `GetDCRPolicyDefault` and `UpdateDCRPolicyDefault` RPCs.
- [ ] `auth_option` permissions on the management RPCs resolve to `policy.read` for Get and `policy.write` for Update / Reset (matches existing convention for domain / password policy management RPCs).
- [ ] `auth_option` permission on the admin RPCs resolves to `iam.policy.write` for Update and `iam.policy.read` for Get.
- [ ] When `OIDC.DCR.Enabled=true` AND the runtime feature flag is OFF for the calling instance's resource owner, all five RPCs return gRPC `FAILED_PRECONDITION` with message key `Errors.DCR.FeatureDisabled` (HTTP-bridge → 403). Symmetric to `cavekit-iat.md` R6 / `cavekit-config.md` R3.
- [ ] When `OIDC.DCR.Enabled=false` at startup, the five RPCs are not registered server-side; calls receive gRPC `UNIMPLEMENTED`.
- [ ] `buf generate` and `pnpm generate` produce a clean diff after the proto edits.

**Dependencies:** R1, R3, R4, R5; `cavekit-config.md` R2, R3.

### R7: Audit and observability
**Description:** Policy mutations emit redacted payloads in the audit log (no full URI lists in error logs — only count + first violating URI for failure cases), and the request-time resolution path is observable via a new metric and a new OTel span attribute.

**Acceptance Criteria:**
- [ ] Every successful `OrgDCRPolicy*` and `InstanceDCRPolicy*` event payload that lands in the audit log includes `{instance_id, resource_owner, allowed_audiences_count, registration_access_token_lifetime, scope: "org"|"instance"}` — `allowed_audiences_count` is an integer, NOT the URI list (privacy: org-level allow-lists may name internal-only URIs).
- [ ] Failure paths (R4 invalid subset, R5 invalid cap) emit a WARN log line with `{instance_id, resource_owner, error_key, first_violating_value}` — never the full submitted list.
- [ ] A new counter `zitadel.dcr.org_policy_changes_total` is exposed with labels `org_id`, `scope` (`org` | `instance`), and `result` (`accepted` | `rejected`).
- [ ] OTel spans `oidc.dcr.register` (per `cavekit-console-ui-docs-and-observability.md` R7) and the RFC 8707 sidecar evaluation span (per `cavekit-rfc8707-resource.md`) gain attribute `dcr.policy.scope` whose value is `org` when an org override resolved at request time, otherwise `instance` or `static-config` — corresponds to the `Scope` field exposed by R3.
- [ ] No span / log / metric attribute carries the org `AllowedAudiences` list verbatim.

**Dependencies:** R1, R3, R6; `cavekit-console-ui-docs-and-observability.md` R6, R7, R8; `cavekit-rfc8707-resource.md`.

### R8: Request-time policy resolution at register and RFC 8707 sidecar
**Description:** The DCR register handler and the RFC 8707 `resource` validation sidecar consult R3's effective policy BEFORE applying the instance / static-config allow-list. The merge order is: request → org policy → instance policy → static config. The Phase 1 RFC 8707 sidecar is constructed with `AllowedAudiences []string` injected at handler-construction time; Phase 2 changes the construction site so the sidecar reads the merged value via R3 per request, keyed by the authenticated context's org.

**Acceptance Criteria:**
- [ ] The DCR register handler resolves the effective policy via R3 using `(instance_id, org_id)` from the IAT-mode IAT claims (`cavekit-register-handler.md` R3) or the anonymous-mode `DefaultOrgID` (`cavekit-config.md` R1) and applies the merged `AllowedAudiences` to any `audience` / `resource` clamping the handler performs at registration.
- [ ] The RFC 8707 sidecar's audience-allow-list check (`cavekit-rfc8707-resource.md` R3) reads the merged value from R3 per request rather than the static instance `OIDC.DCR.AllowedAudiences` slice.
- [ ] When the org has no override, the merged value is byte-identical to the Phase 1 instance allow-list — the Phase 1 acceptance behavior is preserved as a special case.
- [ ] When the org defines an override that shrinks the allow-list, a request whose `resource` is in the instance allow-list but NOT in the org allow-list is rejected with `invalid_target` (RFC 7591 §3 invalid_redirect_uri equivalent for register-time clamping; RFC 8707 §2 `invalid_target` for `/authorize` and `/token`). The error path mirrors `cavekit-rfc8707-resource.md` R6 exactly.
- [ ] An integration test exercises three resolutions: (a) no org override → instance allow-list applied; (b) org override narrows the list → narrowed list applied; (c) org override out-of-bounds is rejected at command time per R4 and never reaches the request path.
- [ ] The `RegistrationAccessTokenLifetime` field of the effective policy supersedes the static `OIDC.DCR.RegistrationAccessToken.Lifetime` in the RAT issuance path of `cavekit-register-handler.md` R6 / `cavekit-manage-handler.md` R5 (PUT rotation).

**Dependencies:** R3, R4, R5; `cavekit-register-handler.md` R3, R4, R6; `cavekit-rfc8707-resource.md` R3, R6; `cavekit-manage-handler.md` R5.

### R9: i18n keys for all 22 locales
**Description:** New error keys introduced by this kit are translated for every locale shipped under `internal/api/ui/login/static/i18n/` — not just `en` and `de`. Translation quality matches Phase 1 T-075 (hand-translated, not machine-passthrough English). A missing key in any of the 22 yaml files is a test failure.

**Acceptance Criteria:**
- [ ] Keys `Errors.DCR.OrgPolicy.InvalidAudienceSubset`, `Errors.DCR.OrgPolicy.InvalidLifetimeCap`, and `Errors.DCR.OrgPolicy.NotAuthorized` are present in all 22 yaml locale files under `internal/api/ui/login/static/i18n/`.
- [ ] `internal/i18n/dcr_keys_test.go` (the existing Phase 1 test) is extended to cover the three new keys; absence in any locale fails the test.
- [ ] Each locale's value is a non-empty, non-raw-key string; the value differs from the English source where the locale's standard practice differs (no machine-passthrough copies).
- [ ] Fallback behavior from `cavekit-console-ui-docs-and-observability.md` R3 is preserved: a request with `Accept-Language` matching a locale whose bundle is missing one of the three keys still emits a rendered English string (never the raw key).

**Dependencies:** R6; `cavekit-console-ui-docs-and-observability.md` R3.

## Out of Scope
- Per-grant-type allow / deny per org (deferred — not requested in this Phase 2 cycle).
- Per-org `AllowedRedirectURIHostPatterns` (potential Phase 3).
- Per-user DCR policy.
- Per-org override of `RequireInitialAccessToken` (instance-only).
- Per-org override of `SoftwareStatement.TrustedIssuers` — see `cavekit-software-statement.md`.
- Per-org override of `JwksURI` SSRF deny-list — see `cavekit-security-hardening.md`.

## Cross-References
- See `cavekit-config.md` R1: static-config defaults for `AllowedAudiences` and `RegistrationAccessToken.Lifetime` are the bottom-tier fallback in R3's merge.
- See `cavekit-rfc8707-resource.md` R3, R6: the `AllowedAudiences` allow-list and `invalid_target` envelope reused at request time per R8.
- See `cavekit-manage-handler.md` R5: PUT-time RAT rotation honors the effective `RegistrationAccessTokenLifetime` from this kit's R8.
- See `cavekit-register-handler.md` R3, R6: register-time policy resolution per R8.
- See `cavekit-console-phase2.md` R5, R6, R7: console UI surface that consumes R6's gRPC.
- See `cavekit-console-ui-docs-and-observability.md` R6, R7, R8: audit / OTel span / metric surface extended by R7.

## Changelog
- 2026-04-28: Initial Phase 2 draft.
