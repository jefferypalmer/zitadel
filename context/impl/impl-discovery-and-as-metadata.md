---
created: "2026-04-26T20:00:00Z"
last_edited: "2026-04-26T20:00:00Z"
---
# Implementation Tracking: OIDC Discovery + RFC 8414 AS Metadata

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-029 | DONE | OIDC discovery `registration_endpoint` advertisement, dual-gated. New `Server.dcrEnabled` (yaml gate, set in NewServer from config.DCR.Enabled) + `Server.dcrAdvertised(ctx)` predicate + `Server.registrationEndpointURL(ctx)` helper. `dcr.HandlerPrefix` const exported (`/oidc/v1/register`) so discovery (R1), AS metadata (R2), and the start.go mount all share one source of truth — cannot diverge per R3. createDiscoveryConfig now sets RegistrationEndpoint via the helper; empty value is dropped by existing `omitempty` JSON tag — NEVER emits `"registration_endpoint": null` (Claude Code Zod parser bug GH#38102). 9 subtests: 5-row dual-gate matrix on registrationEndpointURL + 3-row JSON-shape pinning + 4-row dcrAdvertised truth table. |
| T-030 | DONE | RFC 8414 AS metadata handler at `/.well-known/oauth-authorization-server`. New `internal/api/oidc/as_metadata` package: HandlerPath const + Metadata struct (RFC 8414 §2 strict subset of OIDC discovery) + MetadataBuilder type + NewHandler(build) http.Handler. Server.AsMetadata(ctx) builder satisfies MetadataBuilder so endpoint values come from the same Server.Endpoints() / op.IssuerFromContext path as createDiscoveryConfig — two documents cannot diverge (R3 byte-identity test deferred to T-047). Mounted on yaml gate (start.go conditional next to dcr.Handler); yaml=false → unmounted → mux 404 (R2 AC). R4 hostname-root warning via issuerWarner (sync.Map keyed on instanceID + issuer separator U+0000, log-once per pair). 4 test groups: BodyShape, RegistrationEndpointOmittedWhenEmpty, IsRootIssuer (6 subtests), IssuerWarner_LogsOncePerInstanceIssuer (3 subtests + DistinctInstancesEachWarn). |
