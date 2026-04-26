---
created: "2026-04-26T20:55:00Z"
last_edited: "2026-04-26T20:55:00Z"
---
# T-044 — DCR TLS Posture Inspection (cavekit-register-handler.md R10)

Build site: context/plans/build-site.md

## Acceptance Criteria

> R10: TLS posture
> - [ ] `/oidc/v1/register` is reachable over the same hostname/port/TLS
>       configuration as `/oidc/v1/userinfo`.
> - [ ] No DCR-specific TLS configuration knobs exist.
> - [ ] The deployment guide documents the production TLS-termination
>       requirement (cross-ref `cavekit-console-ui-docs-and-observability.md`
>       R3).

## Inspection results

### AC1 — same hostname/port/TLS as `/oidc/v1/userinfo`

Both endpoints are mounted on the same `apis` API server in
`cmd/start/start.go`:

- `/oidc/v1/register` — `cmd/start/start.go:693`
  ```go
  apis.RegisterHandlerOnPrefix(dcr.HandlerPrefix, dcr.Handler())
  ```
- `/oidc/v1/userinfo` — registered via `oidcPrefixes` at
  `cmd/start/start.go:702`:
  ```go
  apis.RegisterHandlerPrefixes(oidcServer, oidcPrefixes...)
  ```

The `apis` server's TLS posture is set once at the API-server-construction
boundary using `config.TLS` (resolved at line 377/460 via `config.TLS.Config()`)
and `config.ExternalSecure`. There is no `RegisterHandlerOnPrefix` overload
that allows a per-handler TLS override — every handler registered with
`apis` shares the same `tls.Config`, the same listener, the same hostname
+ port. This is structural, not a soft contract.

The mount-time gate (`if config.OIDC.DCR.Enabled`) only governs
*whether* the handler is mounted, not *how* it is served.

### AC2 — no DCR-specific TLS knobs

Pinned by **`TestDCRConfig_NoTLSKnobs_R10`** in
`internal/api/oidc/dcr_config_test.go`. The test reflectively scans the
`DCRConfig` struct and the only sub-struct that could plausibly grow a
TLS knob (`DCRJwksURIConfig`) and asserts no field name contains
`"TLS"`, `"Cert"`, `"HTTPS"`, `"Insecure"`, `"MTLS"`, or `"Mtls"`. Any
future contributor adding a TLS-shaped knob fails the build.

Manual confirmation of `DCRConfig` fields at
`internal/api/oidc/op.go:58-76` and the four sub-structs (lines 78-97):
no TLS-relevant field present.

The only network-related knob anywhere in the DCR config tree is
`DCRJwksURIConfig.{HTTPTimeout, AllowLoopbackInDev, DisallowedIPRanges}`,
which governs **outbound** JWKS fetch hardening (T-015 SSRF guard),
NOT the inbound DCR endpoint TLS.

### AC3 — deployment guide TLS-termination requirement

Doc-side; lands with **T-079** (DCR MDX page,
`cavekit-console-ui-docs-and-observability.md` R5). The deployment-guide
note "Production deployments MUST terminate TLS in front of Zitadel (or
use Zitadel's built-in TLS) per RFC 7591 §5" is owned by that task.

For T-044 this AC is recorded as a forward-reference: the doc text
required by R10 AC3 will be authored under T-079; the build-site
already wires that dependency (`T-079` blocks documentation tier
close-out per Tier 6 ordering).

## Verdict

| AC | Status | Evidence |
|----|--------|----------|
| AC1 (same TLS as userinfo) | VERIFIED | structural — single `apis` server, no per-handler TLS override |
| AC2 (no DCR-specific TLS knobs) | VERIFIED + PINNED | `TestDCRConfig_NoTLSKnobs_R10` (reflection scan) |
| AC3 (deployment-guide note) | DEFERRED to T-079 | doc-tier task owns this string |

## Files touched by T-044

- `internal/api/oidc/dcr_config_test.go` — added `TestDCRConfig_NoTLSKnobs_R10`
- `context/impl/m_t044_tls_posture_inspection.md` — this artifact
- `context/impl/impl-register-handler.md` — T-044 entry
- `context/impl/loop-log.md` — iteration entry
