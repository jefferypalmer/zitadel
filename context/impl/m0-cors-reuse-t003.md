---
created: "2026-04-24T00:00:00Z"
last_edited: "2026-04-24T00:00:00Z"
---
# T-003 — DCR CORS Reuse Inspection

Build site: context/plans/build-site.md
Cavekit: cavekit-security-hardening.md R1

## Finding: DCR handler will reuse existing CORS, no new config tree required.

### Existing middleware

`internal/api/http/middleware/cors_interceptor.go` exposes two public
entry points used throughout the public HTTP surface:

- `CORSInterceptor(h http.Handler) http.Handler` — wraps a handler with
  `DefaultCORSOptions`.
- `CORSInterceptorOpts(opts cors.Options, h http.Handler) http.Handler` —
  allows per-handler overrides (escape hatch for future MCP-inspector
  origin-override needs without new DCR-specific config).

Both delegate to `github.com/rs/cors` `cors.New(opts).Handler(h)`.

### DefaultCORSOptions analysis (cavekit-security-hardening.md R1 §3)

`DefaultCORSOptions` sets:
- `AllowCredentials: true`
- `AllowOriginFunc: func(_ string) bool { return true }`
- Allowed headers: Origin, Content-Type, Accept, Accept-Language,
  Authorization, x-zitadel-orgid, x-user-agent, x-grpc-web,
  x-requested-with, connect-protocol-version, connect-timeout-ms,
  grpc-timeout.
- Allowed methods: OPTIONS, GET, HEAD, POST, PUT, PATCH, DELETE (full
  RFC 7591/7592 surface covered).
- Exposed: Location, Content-Length, Grpc-Status, Grpc-Message,
  Grpc-Status-Details-Bin.

The combination `AllowCredentials:true` + `AllowOriginFunc(...)=true`
does NOT produce `Access-Control-Allow-Origin: *` — `rs/cors` reflects
the requesting `Origin` header verbatim on match and omits the literal
wildcard when credentials are allowed. This satisfies the R1
acceptance criterion: responses never pair `ACAO: *` with `ACAC: true`.

Risk note: the `AllowOriginFunc` currently always returns `true`, so
any origin that sends a preflight gets credentialed CORS. This is a
pre-existing Zitadel policy (not introduced by DCR) and matches the
pattern used by `/oauth/v2/authorize`, `/oidc/v1/userinfo`, etc. DCR
does not need to diverge.

### Decision

- DCR HTTP handlers (`/oidc/v1/register` from cavekit-register-handler.md
  R1, `/oidc/v1/register/{client_id}` from cavekit-manage-handler.md R1,
  `/.well-known/oauth-authorization-server` from
  cavekit-discovery-and-as-metadata.md R2) wrap in `middleware.CORSInterceptor(...)`
  via the existing handler-mount pattern in `cmd/start/start.go`.
- No `OIDC.DCR.CORS` config tree is added (cavekit-config.md R1 last
  bullet enforces this).
- If Claude Code's MCP Inspector ever needs a per-endpoint origin
  override, it flows through `CORSInterceptorOpts(...)` — no new
  config key.

### R1 acceptance-criteria check

- [x] DCR handler wraps in `CORSInterceptor` / `CORSInterceptorOpts` — will
      be applied at mount time in T-031 (register) and T-050 (manage).
- [x] No `OIDC.DCR.CORS` config tree exists — verified against T-001
      output (yaml assert `'CORS' not in dcr`).
- [x] CORS responses never pair `ACAO: *` with `ACAC: true` — guaranteed
      by `rs/cors` library semantics under `AllowCredentials:true` +
      `AllowOriginFunc`.
- [x] Per-endpoint overrides (MCP Inspector) route through existing
      options, not new DCR config — `CORSInterceptorOpts` exists.

T-031 / T-050 MUST NOT introduce a new CORS interceptor; they MUST
wrap the DCR mux with `middleware.CORSInterceptor`. This decision
pins that contract.
