---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-05-05T00:00:00Z"
complexity: unknown
---

# Cavekit Overview: OAuth 2.0 Dynamic Client Registration (RFC 7591/7592) for Zitadel

## Project Header

**Feature:** OAuth 2.0 Dynamic Client Registration (RFC 7591 / 7592 / 8414 / 8707) for Zitadel.

**Primary driver:** Claude Code / MCP ecosystem requires DCR for self-service OAuth client creation against MCP-fronting Zitadel deployments.

**Secondary driver:** RFC 7591 / 7592 / OIDC Registration 1.0 conformance.

**Phase 1 scope:** Anonymous-by-default DCR with optional Initial Access Token (IAT) hardening, RFC 7591/7592 endpoints, RFC 8414 Authorization Server metadata, RFC 8707 Resource Indicators, race-safe IAT consume, jwks_uri SSRF guard, log redaction across HTTP + gRPC + audit-log, minimal Console UI, MDX docs, OTel observability under the `zitadel.dcr.*` metric namespace.

**Source plan:** `context/refs/dcr-plan.md` (1440 lines, 13 senior-review audit passes; convergence achieved).

**Current release:** v5.0.0-dcr.3 (audit-cleanup release, 2026-05-05). Adds two new kits (`cavekit-eventstore-framework-guard.md`, `cavekit-i18n-pipeline.md`) and revises four Phase 1 / Phase 2 kits with v3 audit-cleanup amendments.

## Domain Index

| # | Cavekit | Status | Requirements | Acceptance Criteria | One-line description |
|---|---|---|---|---|---|
| 1 | `cavekit-config.md` | DRAFT | 7 | 38 | `OIDC.DCR.*` config tree, feature flag `KeyDynamicClientRegistration=17`, dual-gate precedence, startup validation, rollback semantics. |
| 2 | `cavekit-iat.md` | DRAFT | 7 | 32 | Initial Access Token domain — events on project aggregate, race-safe `max_uses` via per-slot UniqueConstraint + 3-retry, projection, query, admin gRPC. |
| 3 | `cavekit-register-handler.md` | DRAFT | 10 | 50 | `POST /oidc/v1/register` — RFC 7591 §2 + OIDC Reg 1.0 §2 defaults, auth routing, validate+clamp, 201 response shape, full status-code matrix, Claude Code compat. |
| 4 | `cavekit-manage-handler.md` | DRAFT | 7 | 27 | RFC 7592 GET/PUT/DELETE — RAT verification with Passwap silent rehash, 401 anti-enumeration, full re-clamp on PUT, RAT rotation, token revocation on DELETE. |
| 5 | `cavekit-discovery-and-as-metadata.md` | DRAFT | 4 | 17 | OIDC discovery `registration_endpoint` (`omitempty`, never null) + new RFC 8414 `/.well-known/oauth-authorization-server` handler; both documents agree. |
| 6 | `cavekit-rfc8707-resource.md` | DRAFT | 7 | 28 | Remove existing `token_exchange.go:44-46` rejection; parse `resource` on `/authorize` + `/token`; thread through 6 grant handlers; `AllowedAudiences` allow-list; `invalid_target` on out-of-list. |
| 7 | `cavekit-security-hardening.md` | DRAFT | 6 | 41 | jwks_uri SSRF guard, log redaction (HTTP + gRPC + audit-log), timing side-channel mitigation, hash rotation, T1–T20 threat-model evidence map. |
| 8 | `cavekit-console-ui-docs-and-observability.md` | DRAFT | 8 | 33 | M5.5 console (Dynamic Clients tab + IAT admin), enumerated i18n keys, Cypress smoke tests, MDX docs (DCR + Claude Code MCP), CHANGELOG, SECURITY.md, ADR, OTel spans + `zitadel.dcr.*` metrics. |
| 9 | `cavekit-org-dcr-policy.md` | DRAFT (Phase 2) | 9 | 52 | New `OrgDCRPolicy` aggregate; per-org narrowing of `AllowedAudiences` (subset) and `RegistrationAccessTokenLifetime` (cap); dual-tier projection with `is_default`; effective-policy query helper; org + instance gRPC. |
| 10 | `cavekit-software-statement.md` | DRAFT (Phase 2) | 11 | 64 | RFC 7591 §2.3 software_statement JWT verification — typed `TrustedIssuers`, header parse + `iss` lookup, JWKS fetch (SSRF-guarded, per-issuer cached), signature + claim verify, JTI replay dedupe, claim-to-metadata override mapping, audit + OTel. |
| 11 | `cavekit-inline-jwks.md` | DRAFT (Phase 2) | 7 | 45 | RFC 7591 §2.1.1 inline `jwks` on POST + RFC 7592 §2.2 inline `jwks` on PUT — decode + mutual exclusion with `jwks_uri`, JWK validation, JSONB storage column, RFC 7592 GET read-back, token-endpoint authoritativeness for `private_key_jwt`. |
| 12 | `cavekit-console-phase2.md` | DRAFT (Phase 2) | 10 | 58 | Operator edit-DCR-app panel (RFC 7592 fields read-only); operator-initiated RAT rotation with plaintext-once dialog; per-org IAT admin module; per-org DCR policy editor; full 22-locale rollout (backend yaml + console JSON); Cypress E2E. |
| 13 | `cavekit-eventstore-framework-guard.md` | DRAFT (v3 audit cleanup) | 3 | 14 | Construction-time guard at `internal/eventstore/handler/v2/handler.go::NewHandler` — refuses to construct a Handler with empty Reducers, no `TriggerWithoutEvents`, and no `GlobalProjection` marker; truth-table tests; back-stop verification that no current projection trips it. |
| 14 | `cavekit-i18n-pipeline.md` | DRAFT (v3 audit cleanup) | 4 | 22 | Reproducible Anthropic-API console-i18n bootstrap — Node ESM script under `console/scripts/`, placeholder + glossary preservation with `temperature=0` determinism, CI reproducibility verification, idempotent merge that never overwrites existing target values. |

**Totals:** 14 domains, 100 requirements, ~616 acceptance criteria (Phase 1 + Phase 2 + v3 audit cleanup; v3 added 7 R + ~36 AC across the 6 touched kits — see per-kit files for current per-kit totals).

## Cross-Reference Map

```
config (1) — root config + feature flag; consumed by EVERY other kit
  ├─→ iat (2)                              R2 feature gate
  ├─→ register-handler (3)                 R1, R3, R4, R5 config knobs + dual-gate
  ├─→ manage-handler (4)                   R1 dual-gate, RegistrationAccessToken.{Enabled,Lifetime}
  ├─→ discovery-and-as-metadata (5)        R3 dual-gate; R5 issuer-path warning
  ├─→ rfc8707-resource (6)                 R3 AllowedAudiences allow-list
  ├─→ security-hardening (7)               R2 JwksURI.DisallowedIPRanges
  └─→ console-ui-docs-and-observability(8) R6 hostname-root note

iat (2) ←→ register-handler (3)            R3 IAT verify + consume on POST /register
iat (2) ←→ console-ui-docs-and-observability (8)  R2, R3, R4 admin UI consumes gRPC

register-handler (3) ←→ manage-handler (4) shared mux router, validate.go, errors.go
register-handler (3) ←→ security-hardening (7)     SSRF (jwks_uri), log redaction, audit fields
register-handler (3) ←→ discovery-and-as-metadata (5)  registration_endpoint advertises this handler
register-handler (3) ←→ console-ui-docs-and-observability (8)  audit events feed UI; Claude Code walkthrough

manage-handler (4) ←→ security-hardening (7)       T7 anti-enumeration (R3) + T12 timing (R4)
manage-handler (4) ←→ console-ui-docs-and-observability (8)  PUT idempotency + DELETE revocation note in CHANGELOG

discovery-and-as-metadata (5) ←→ rfc8707-resource (6)  AS metadata indirectly signals MCP-readiness
discovery-and-as-metadata (5) ←→ security-hardening (7)  T17 (registration_endpoint never null)

security-hardening (7) cross-cuts → 3, 4, 5, and consumes 1
console-ui-docs-and-observability (8) consumes 2, 3, 4, references 5, 6, 7 in docs

eventstore-framework-guard (13) ←→ software-statement (10)  R12 forbids the misuse at the kit level; R13 enforces it structurally at NewHandler
eventstore-framework-guard (13) ←→ iat (2)                  R8 (eventstore-derivable identities use UniqueConstraints) — contrast pattern
i18n-pipeline (14) ←→ console-ui-docs-and-observability (8)  R3 strengthened to require full-locale coverage; this kit defines the bootstrap mechanism
```

## Dependency Graph

```
                 ┌──────────────────┐
                 │ 1. config        │  (root)
                 └────────┬─────────┘
                          │
        ┌─────────────────┼─────────────────┬─────────────┐
        │                 │                 │             │
        ▼                 ▼                 ▼             ▼
┌──────────────┐  ┌──────────────────┐  ┌─────────┐  ┌─────────────┐
│ 2. iat       │  │ 5. discovery     │  │ 6. 8707 │  │ 7. security │
└──────┬───────┘  │    + as_metadata │  │ resource│  │  hardening  │
       │          └──────────────────┘  └─────────┘  └──────┬──────┘
       │                                                     │ cross-cut
       ▼                                                     │ on 3, 4, 5
┌──────────────┐                                             │
│ 3. register- │◄────────────────────────────────────────────┤
│    handler   │                                             │
└──────┬───────┘                                             │
       │                                                     │
       ▼ (same package; shared validate / errors / clamps)   │
┌──────────────┐                                             │
│ 4. manage-   │◄────────────────────────────────────────────┘
│    handler   │
└──────┬───────┘
       │
       ▼
┌────────────────────────────────────────┐
│ 8. console-ui-docs-and-observability   │
│    (consumes 2, 3, 4; references 5,6,7)│
└────────────────────────────────────────┘
```

**Cycles:** none. The graph is a DAG rooted at `config`.

## Phase 2

Phase 2 adds 4 new kits (#9–#12) and depends on 6 of the Phase 1 kits via cross-references. Phase 1 R / AC counts are frozen — Phase 1 kits received light "see also" edits on existing Out-of-Scope bullets only.

```
Phase 1                            Phase 2
─────────────────────────────────────────────────────────────────
1. config                  ───→    9. org-dcr-policy
                           ───→   10. software-statement
6. rfc8707-resource        ───→    9. org-dcr-policy
3. register-handler        ───→   10. software-statement
                           ───→   11. inline-jwks
4. manage-handler          ───→   11. inline-jwks

9. org-dcr-policy          ───→   12. console-phase2
10. software-statement     ───→   12. console-phase2
11. inline-jwks            ───→   12. console-phase2
8. console-ui-docs-and-observability  ───→   12. console-phase2
   (Phase 2 console kit extends Phase 1 console kit)
```

Edge rationale:
- `1 → 9`: org policy fields (`AllowedAudiences`, RAT lifetime) fall through to static config defaults via the merge in `cavekit-org-dcr-policy.md` R3.
- `1 → 10`: `OIDC.DCR.SoftwareStatement.*` config tree (refined from Phase 1 stub).
- `6 → 9`: org policy NARROWS the instance allow-list defined by `cavekit-rfc8707-resource.md` R3; sidecar consults merged value at request time per `cavekit-org-dcr-policy.md` R8.
- `3 → 10`: register handler invokes the software_statement verifier and consumes its `MergedMetadata`.
- `3 → 11`: register handler decodes inline `jwks` and applies the mutual-exclusion check.
- `4 → 11`: PUT manage handler accepts inline `jwks` for full-replacement semantics; storage transitions emit events.
- `9 / 10 / 11 → 12`: console Phase 2 surfaces the new gRPC (org policy), translates the new error keys (software_statement, inline_jwks), and rolls out console JSON i18n to 22 locales.
- `8 → 12`: Phase 2 console kit reuses the IAT plaintext-dialog hardening, Cypress conventions, and i18n fallback contract from Phase 1 console kit.

**Cycles:** none. Phase 2 graph remains a DAG rooted at `1. config`.

### Cross-cut nature of kits 6 and 7

- **`cavekit-rfc8707-resource.md` (kit 6)** is *orthogonal* to the DCR registration endpoints. It depends on `config` (for `AllowedAudiences`) but otherwise touches non-DCR code paths: it removes the existing rejection at `internal/api/oidc/token_exchange.go:44-46`, adds parsing on `/authorize` + `/token`, threads `resource` through `domain.AuthRequest` → `OIDCSession.Audience`, and propagates into all six token grant handlers (`token_code.go`, refresh-token, `token_client_credentials.go`, `token_device.go`, `token_exchange.go`, `token_jwt_profile.go`). It is grouped with DCR because Claude Code MCP requires it for audience isolation, but no other DCR kit *consumes* it directly.

- **`cavekit-security-hardening.md` (kit 7)** is a true cross-cut. Its requirements apply *to* multiple kits: SSRF guard (R2) is invoked from kit 3 register-handler R5 and kit 4 manage-handler R5; log redaction (R3) covers kit 2 iat R6 (gRPC), kit 3 register-handler R7 (HTTP), kit 4 manage-handler R5 (RAT plaintext); timing side-channel (R4) applies to kit 4 manage-handler R3; hash rotation (R5) applies to kit 4 manage-handler R2 and kit 2 iat R7. The T1–T20 evidence map (R6) cross-references essentially every other kit.

## Validation Notes

- Every cross-reference in every kit points to an existing kit file in this directory.
- No circular dependencies — verified by hand against the DAG above.
- Out of Scope sections in every kit explicitly list Phase-2 deferrals (CIBA, FAPI-DCR, SCIM, per-org overrides, inline `jwks`, `software_statement` verification, `client_name#<lang>`, `client_credentials` default).
- Brownfield criteria use `[VERIFIED]` / `[GAP]` markers; file:line references from the plan are preserved as locator hints inside acceptance criteria (they are part of the spec contract, not implementation suggestions).
- Acceptance criteria are agent-testable (HTTP status, header presence, file presence, test commands, named test files, observable log/metric/event payloads). No subjective criteria.

## Changelog
- 2026-04-24: Initial draft from `context/refs/dcr-plan.md`.
- 2026-04-28: Phase 2 — added kits 9–12 (`cavekit-org-dcr-policy.md`, `cavekit-software-statement.md`, `cavekit-inline-jwks.md`, `cavekit-console-phase2.md`); appended Phase 2 dependency-graph subsection. Phase 1 kit R/AC counts FROZEN; Phase 1 kits received cross-reference-only edits to existing Out-of-Scope bullets (no R/AC changes). Phase 1 fork tag at `dcr-rfc8707-v1.0.0`.
- 2026-05-05 (v5.0.0-dcr.3 audit cleanup): Added kits 13 (`cavekit-eventstore-framework-guard.md`) and 14 (`cavekit-i18n-pipeline.md`); appended cross-reference rows to the Cross-Reference Map. Revised four kits with v3 audit-cleanup amendments — `cavekit-software-statement.md` (strengthened R9; added R12 application-managed-tables and R13 aud-validation), `cavekit-iat.md` (added R8 UniqueConstraint-vs-TTL pattern note), `cavekit-console-ui-docs-and-observability.md` (strengthened R3 full-locale coverage; added R9 frontend hygiene and R10 Cypress teardown), `cavekit-manage-handler.md` (added R8 `ManageFromContext` panic-on-missing). Current release tag: v5.0.0-dcr.3.
