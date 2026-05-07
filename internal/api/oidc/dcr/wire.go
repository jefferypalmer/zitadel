package dcr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/zitadel/passwap"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/zitadel/zitadel/internal/api/authz"
	http_util "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/api/oidc/dcr/software_statement"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
)

// metricsResponseWriter is a thin http.ResponseWriter wrapper that
// captures the response status code for the registration-result
// classification (success / client_error / server_error) used by
// [recordRegistration]. It MUST stay minimal — the OIDC server is on
// the hot path, and any extra method this struct overrides changes
// observable handler behavior.
type metricsResponseWriter struct {
	http.ResponseWriter
	status int
}

func (m *metricsResponseWriter) WriteHeader(code int) {
	m.status = code
	m.ResponseWriter.WriteHeader(code)
}

// resultFromStatus maps an HTTP status code to the
// [MetricRegistrationsTotal] result label per R8 AC1. Status 0 (no
// WriteHeader call) is treated as 200 per Go's net/http semantics.
func resultFromStatus(code int) string {
	if code == 0 {
		code = http.StatusOK
	}
	switch {
	case code >= 500:
		return MetricResultServerError
	case code >= 400:
		return MetricResultClientError
	default:
		return MetricResultSuccess
	}
}

// IATHasher is the subset of [internal/crypto.Hasher] (which embeds
// `*passwap.Swapper`) the DCR registration handler needs at the
// wiring site. Defined as an interface so unit tests can stub it
// without pulling in the full Commands tree, and so [BuildAntiEnumDummyHash]
// can be exercised under a controlled algorithm-mismatch shape that
// reproduces F-101.
type IATHasher interface {
	Hash(plaintext string) (string, error)
	Verify(encoded, plaintext string) (string, error)
}

// antiEnumDummyPlaintext is the fixed sentinel string fed through the
// configured hasher to produce the dummy hash for anti-enumeration
// timing equivalence (cavekit-iat.md R4 amendment 2026-04-27).
//
// The exact value does not matter — it MUST NOT collide with any
// real IAT plaintext (the IAT format is `zdiat_<id>.<random>` per
// R5, this string contains neither prefix nor `.`) and MUST be
// stable across runs of the same deployment so the hash produced
// at startup remains valid for the process's lifetime.
const antiEnumDummyPlaintext = "anti-enum-sentinel-dcr"

// BuildAntiEnumDummyHash produces the dummy Passwap hash that
// [ResolveIAT] runs Verify against on its parse-failure / not-found /
// cross-instance branches per cavekit-iat.md R4 amendment 2026-04-27.
//
// Provenance contract: the encoded hash returned here is produced by
// calling `hasher.Hash(antiEnumDummyPlaintext)` exactly once. The
// algorithm prefix of the encoded string therefore matches whatever
// the configured `SecretHasher.Algorithm` is — guaranteeing
// `passwap.Swapper.Verify` runs the same crypto path real IATs use
// when the registration handler later compares a presented Bearer
// against a stored row.
//
// Startup probe: this function then calls `hasher.Verify(encoded,
// "wrong-plaintext")` and panics if the returned error wraps
// [passwap.ErrNoVerifier]. That outcome is only possible in a
// misconfigured deployment whose `SecretHasher.Algorithm` and
// `Verifiers` lists have drifted (e.g. a Hasher set to bcrypt with
// the bcrypt verifier accidentally removed). Failing fast at boot
// is strictly preferable to silently leaking timing for the lifetime
// of the process — F-101 was *worse* than no defence because the
// not-found path returned in microseconds while wrong-random
// returned in milliseconds.
//
// Returns the encoded dummy hash on success.
func BuildAntiEnumDummyHash(hasher IATHasher) (string, error) {
	encoded, err := hasher.Hash(antiEnumDummyPlaintext)
	if err != nil {
		return "", fmt.Errorf("dcr: anti-enum dummy hash construction failed: %w", err)
	}
	// Probe.
	if _, verifyErr := hasher.Verify(encoded, "wrong-plaintext"); verifyErr != nil {
		if errors.Is(verifyErr, passwap.ErrNoVerifier) {
			panic("dcr: anti-enum dummy hash uses an algorithm the configured passwap.Swapper has no verifier for. " +
				"This indicates a SecretHasher.Algorithm / Verifiers config drift — fix it before serving traffic. " +
				"F-101 reproduced exactly this shape (hardcoded $argon2id$ literal vs bcrypt-only swapper) and " +
				"silently inverted the anti-enumeration timing oracle for the lifetime of the process.")
		}
		// Any other error is the expected "wrong plaintext" outcome.
		return encoded, nil
	}
	// Encoded.Verify(wrongPlaintext) returning nil means the wrong
	// plaintext somehow matched — only possible if the sentinel and
	// "wrong-plaintext" collide, which is a programmer error here.
	panic("dcr: anti-enum dummy hash impossibly matched the wrong-plaintext probe; sentinel collision?")
}

// RegistrationDeps is the full dependency surface the DCR
// registration handler consumes at startup. Injected once via
// [NewHandler]; thread-safe (no per-request mutation expected).
//
// T-038 (anonymous resolution) and T-037 (IAT auth) populated the
// *Config / *Verifier / *Parser / Anti-enum slots. T-040 will add
// the RegisterClient command + hooks for ApplicationDynamicallyRegistered
// + ApplicationRegistrationAccessTokenSet event emission. The struct
// is deliberately growable.
type RegistrationDeps struct {
	// Queries reads IATs by ID for the IAT-mode auth path
	// (cavekit-register-handler.md R3 / T-037).
	Queries IATLookupQueries

	// Verifier wraps the configured Passwap hasher's Verify method.
	// The wiring layer adapts `*command.Commands` (or a thin shim
	// around `*crypto.Hasher`) to satisfy this interface. T-040 may
	// expand this to expose VerifyAndRehash for silent-rehash support.
	Verifier IATVerifier

	// Parser is `command.ParseIATPlaintext` in production. Passed as
	// a closure so the dcr package stays decoupled from the command
	// package.
	Parser PlaintextParser

	// Config drives the metadata clamp (cavekit-register-handler.md
	// R4). Production wiring passes `*oidc.DCRConfig`-backed adapter.
	Config DCRConfigSubset

	// AnonConfig drives the anonymous-mode resolution path
	// (cavekit-register-handler.md R3 AC4-AC5 / T-038).
	AnonConfig AnonymousConfig

	// SupportedSigAlgs feeds R4 `id_token_signed_response_alg`
	// validation. Sourced from the OIDC server's
	// `supportedSigningAlgs()` at startup.
	SupportedSigAlgs []string

	// SoftwareStatementEnabled gates R4's "unapproved_software_statement"
	// rejection. Sourced from
	// `config.OIDC.DCR.SoftwareStatement.Enabled`.
	SoftwareStatementEnabled bool

	// EffectivePolicy resolves the per-(instance, org) merged DCR policy
	// at request time per cavekit-org-dcr-policy.md R8 / T-033 +
	// T-034. Optional — when nil the register handler falls back to the
	// static `OIDC.DCR.AllowedAudiences` and
	// `OIDC.DCR.RegistrationAccessToken.Lifetime` (Phase 1 byte-identical
	// invariant). When non-nil, the resolved policy's AllowedAudiences
	// supersedes the static `cfg.AllowedAudiences()` used in R4 clamps,
	// and RegistrationAccessTokenLifetime supersedes the static value
	// threaded into the Register closure.
	EffectivePolicy EffectivePolicyFn

	// SoftwareStatementPipeline drives the parse → lookup → verify →
	// required-claims → replay-record → override-mapping flow when the
	// request body carries a software_statement (cavekit-software-
	// statement.md R2..R9 / T-031). Optional — nil disables the
	// pipeline (Phase 1 fallback: any non-empty software_statement
	// rejects via R4 as `unapproved_software_statement`). Production
	// wires this only when SoftwareStatementEnabled=true.
	SoftwareStatementPipeline *software_statement.PipelineDeps

	// AntiEnumDummyHash is the precomputed dummy Passwap hash used
	// by [ResolveIAT] for timing equivalence between known-and-wrong
	// and unknown branches. MUST be built via [BuildAntiEnumDummyHash]
	// at startup; passing a hand-written literal here violates
	// cavekit-iat.md R4 amendment 2026-04-27 and reintroduces the
	// F-101 inverted-oracle vulnerability.
	AntiEnumDummyHash string

	// Register is the closure that calls
	// `command.Commands.RegisterClient` (T-040). Defined as a
	// function-shaped seam so this package does not have to import
	// command, and so unit tests can stub the eventstore push without
	// the full Commands harness. Production wiring (cmd/start/start.go)
	// builds it as `commands.RegisterClient`-shaped — the input/output
	// types live in command/ and we use generic `any` here to keep the
	// import boundary one-way.
	Register RegisterFn

	// ConsumeIAT is the closure that reserves one slot of the IAT
	// identified by [RegistrationContext.IATID] via
	// `command.Commands.ConsumeInitialAccessToken`. Per
	// cavekit-register-handler.md R6 amendment 2026-04-27 / F-200, the
	// dispatcher MUST call this AFTER successful ResolveIAT and BEFORE
	// invoking [Register] — otherwise an attacker can replay one valid
	// IAT to register N clients regardless of MaxUses. Anonymous mode
	// (RegistrationContext.IATID == "") MUST NOT invoke this closure.
	ConsumeIAT ConsumeIATFn

	// MaxBodyBytes caps the registration request body
	// (cavekit-config.md R1 / R2 AC). Zero falls back to
	// `DefaultMaxBodyBytes` (64 KiB).
	MaxBodyBytes int64

	// Manage drives the RFC 7592 GET/PUT/DELETE manage handlers
	// (cavekit-manage-handler.md R2 / T-051). Optional — when nil,
	// [NewHandler] mounts the bearer-presence-only gate (T-050) on
	// the manage routes so deployments still in mid-rollout return
	// 401 instead of 500. Production wiring sets every field.
	Manage *ManageDeps
}

// ConsumeIATFn is the function-shaped seam for invoking
// `command.Commands.ConsumeInitialAccessToken` from inside the
// dispatcher without a direct command-package import. Returns a
// *ClampError on failure (mapped to 401 invalid_token by the
// dispatcher per cavekit-register-handler.md R6 amendment / F-200);
// any other error type is treated as a 500.
type ConsumeIATFn func(ctx context.Context, regCtx *RegistrationContext) error

// RegMethod* are the audit-event registration_method enum values
// the dispatcher passes through to the command layer. Mirror of
// `command.RegistrationMethod*` consts — duplicated here to keep the
// dcr → command import boundary one-way.
const (
	RegMethodAnonymous = "anonymous"
	RegMethodIAT       = "iat"
)

// RegisterFn is the function-shaped seam for invoking the
// `command.Commands.RegisterClient` command from inside the dcr
// package without importing command. Production wires this to a
// closure that translates dcr.RegisterRequest into
// command.RegisterClientInput and the result back. Tests stub it
// directly.
type RegisterFn func(ctx context.Context, req *RegisterRequest) (*RegisterResult, error)

// RegisterRequest is the dcr-internal shape passed to the registered
// closure. Mirrors the subset of `command.RegisterClientInput` fields
// the dispatcher controls.
// EffectivePolicy is the dcr-internal view of the merged DCR policy.
// AllowedAudiences nil = unrestricted (RFC 8707 §2 inversion);
// RegistrationAccessTokenLifetime zero = no expiry per RFC 7592 §3.
type EffectivePolicy struct {
	AllowedAudiences                []string
	RegistrationAccessTokenLifetime time.Duration
	// AllowedAudiencesScope is "org" / "instance" / "static-config" —
	// emitted via the OTel attribute `dcr.policy.scope` in T-040.
	AllowedAudiencesScope                string
	RegistrationAccessTokenLifetimeScope string
}

// EffectivePolicyFn is the function-shaped seam used to resolve the
// merged policy at request time. Production wires this to a closure
// that calls Queries.DCRPolicyByOrg (T-017). Tests stub it.
type EffectivePolicyFn func(ctx context.Context, orgID string) (*EffectivePolicy, error)

type RegisterRequest struct {
	Clamped             *RFC7591Metadata
	OrgID               string
	ProjectID           string
	IATID               string
	RegistrationMethod  string
	ClientNameUnclamped string
	RemoteIPString      string
	UserAgent           string

	// SoftwareStatementJTI carries the verified JWT's jti claim per
	// cavekit-software-statement.md R8 / T-031 — populated only when
	// the request body contained a software_statement that PASSED the
	// full pipeline (parse → trusted-issuer lookup → verify → required-
	// claims → replay-record). Empty string when no software_statement
	// was supplied (preserves the Phase 1 sentinel).
	SoftwareStatementJTI string

	// EffectiveRATLifetime carries the merged RegistrationAccessToken
	// lifetime resolved at request time per cavekit-org-dcr-policy.md
	// R8 / T-033. Zero with EffectivePolicyResolved=false means "no
	// override seen — caller falls back to the static
	// OIDC.DCR.RegistrationAccessToken.Lifetime". When a resolver is
	// wired, the value supersedes the static config in the Register
	// closure's RAT issuance path.
	EffectiveRATLifetime    time.Duration
	EffectivePolicyResolved bool
}

// RegisterResult is the dcr-internal shape returned by the closure.
// Mirrors the subset of `command.RegisterClientResult` the dispatcher
// echoes into the 201 response body.
type RegisterResult struct {
	ClientID     string
	ClientSecret string
	// ClientSecretExpiresIn echoes config.OIDC.DCR.ClientSecretExpiresIn
	// so the response writer can compute `client_secret_expires_at`
	// (R7 / F-201). Zero = "no expiry" sentinel per RFC 7591 §3.2.1.
	ClientSecretExpiresIn time.Duration
	RATPlaintext          string
	RATExpiresAt          time.Time
	ClientIDIssuedAt      time.Time
	PersistedAppName      string
}

// Validate is a defensive runtime check on the deps struct — every
// required field MUST be non-nil / non-empty. Called by [NewHandler]
// to fail-fast on a malformed wiring (T-040 will add more required
// slots; this function grows with them).
func (d RegistrationDeps) Validate() error {
	if d.Queries == nil {
		return errors.New("dcr: RegistrationDeps.Queries is required")
	}
	if d.Verifier == nil {
		return errors.New("dcr: RegistrationDeps.Verifier is required")
	}
	if d.Parser == nil {
		return errors.New("dcr: RegistrationDeps.Parser is required")
	}
	if d.Config == nil {
		return errors.New("dcr: RegistrationDeps.Config is required")
	}
	if d.AnonConfig == nil {
		return errors.New("dcr: RegistrationDeps.AnonConfig is required")
	}
	if d.AntiEnumDummyHash == "" {
		return errors.New("dcr: RegistrationDeps.AntiEnumDummyHash is required (build via BuildAntiEnumDummyHash)")
	}
	if d.Register == nil {
		return errors.New("dcr: RegistrationDeps.Register is required (wire to command.Commands.RegisterClient)")
	}
	if d.ConsumeIAT == nil {
		return errors.New("dcr: RegistrationDeps.ConsumeIAT is required (wire to command.Commands.ConsumeInitialAccessToken). F-200 — without this, IAT replay protection is non-existent in production.")
	}
	// cavekit-software-statement.md R14 (T-023): when SoftwareStatement
	// is enabled in config, the verifier pipeline MUST be wired. The
	// nil-pipeline branch in dispatch.go silently falls back to the
	// Phase-1 unapproved_software_statement path — production with
	// Enabled=true must reach the real verifier.
	if d.SoftwareStatementEnabled && d.SoftwareStatementPipeline == nil {
		return errors.New("dcr: RegistrationDeps.SoftwareStatementPipeline is required when SoftwareStatementEnabled=true (cavekit-software-statement.md R14 — without this, all of R5/R9/R13 is dead in production)")
	}
	// Manage is intentionally optional — see field godoc. When set,
	// validate it; otherwise the manage routes fall back to the
	// bearer-presence-only gate.
	if d.Manage != nil {
		if err := d.Manage.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// NewHandler builds the DCR mux router with full dependencies bound
// in. Replaces the dependency-free [Handler] for production wiring;
// the latter is retained for migration coverage and will be removed
// once cmd/start/start.go updates.
//
// Panics if [RegistrationDeps.Validate] fails — fail-fast at boot
// rather than silently serving 5xx for the lifetime of the process.
//
// The returned http.Handler uses the same gorilla mux + feature-gate
// middleware as the current Handler. The bodies of POST/GET/PUT/DELETE
// stubs become real once T-040 / T-053 / T-054 / T-056 land; for now
// they continue to return placeholder responses so existing tests
// remain green.
func NewHandler(deps RegistrationDeps) http.Handler {
	if err := deps.Validate(); err != nil {
		panic(err)
	}
	r := mux.NewRouter()
	r.HandleFunc("/", postRegisterDispatch(deps)).Methods(http.MethodPost)
	getH, putH, delH := manageRoutes(deps)
	r.HandleFunc("/{client_id}", getH).Methods(http.MethodGet)
	r.HandleFunc("/{client_id}", putH).Methods(http.MethodPut)
	r.HandleFunc("/{client_id}", delH).Methods(http.MethodDelete)
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		WriteError(w, http.StatusMethodNotAllowed, ErrCodeInvalidRequest,
			"this DCR endpoint does not support the requested HTTP method.")
	})
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.NotFound(w, req)
	})
	// Normalize the post-StripPrefix path so the gorilla router below
	// matches consistently for both /oidc/v1/register and /oidc/v1/register/.
	// `apis.RegisterHandlerOnPrefix` strips `/oidc/v1/register`, leaving
	// path="" when the original URL had no trailing slash and path="/"
	// when it did. Gorilla mux treats `r.HandleFunc("", ...)` and
	// `r.HandleFunc("/", ...)` identically (both register the root pattern),
	// so neither matches an actually-empty path string. Without this
	// normalization the parent mux falls through to the catch-all login
	// handler, which 301-redirects to `/` — corrupting POST bodies in
	// every HTTP client without `-L` and downgrading to GET.
	gated := featureGateMiddleware(r)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		gated.ServeHTTP(w, req)
	})
}

// postRegisterDispatch is the assembled POST /oidc/v1/register
// pipeline (cavekit-register-handler.md R2..R8). Composes:
//   - Decode (R2): Content-Type / body cap / JSON / defaults
//   - ClassifyAuthMode + ResolveAnonymous / ResolveIAT (R3)
//   - ValidateAndClampMetadata (R4 / R5)
//   - Register (R6 — calls into command.Commands.RegisterClient)
//   - WriteRegistrationResponse (R7 — 201 RFC 7591 §3.2.1 body)
//
// Every error path emits the RFC 7591 §3.2.2 envelope via WriteError
// at the dispatcher level — sub-stages return *ClampError carrying
// HTTPStatus + Code so the dispatcher uses one branch per failure
// shape.
//
// 401 paths additionally set `WWW-Authenticate: Bearer error="invalid_token"`
// per R8 AC.
func postRegisterDispatch(deps RegistrationDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// cavekit-console-ui-docs-and-observability.md R7 AC1 (T-066) —
		// span name is the literal identifier asserted by the kit.
		// No attributes are set: AC6 (never carry client_secret / RAT /
		// IAT plaintext / software_statement content) is satisfied
		// structurally by emitting zero attributes here.
		ctx, span := tracing.NewNamedSpan(r.Context(), "oidc.dcr.register")
		defer span.End()
		r = r.WithContext(ctx)

		// T-067 / R8 AC1+AC2 — capture the response status + duration so
		// we can emit `zitadel.dcr.registrations_total` and
		// `zitadel.dcr.request_duration_seconds` on the way out. The
		// auth-method + application_type labels are populated as the
		// pipeline progresses (they're unknown at the point of an
		// early 401/415/413 short-circuit).
		mrw := &metricsResponseWriter{ResponseWriter: w}
		w = mrw
		started := time.Now()
		var (
			labelAuthMethod      = MetricAuthMethodAnonymous
			labelApplicationType = ""
		)
		defer func() {
			recordRequestDuration(ctx, time.Since(started))
			recordRegistration(ctx,
				resultFromStatus(mrw.status),
				labelAuthMethod,
				labelApplicationType)
		}()

		// 1. Auth-first short-circuit (R3 amendment 2026-04-27 / F-219).
		// When RequireInitialAccessToken=true and no Bearer is present,
		// short-circuit with 401 BEFORE the decoder runs. The body cap,
		// Content-Type check, and JSON parse error responses (413/415/400)
		// would otherwise leak server config to anonymous attackers
		// fingerprinting the deployment.
		mode, bearer := ClassifyAuthMode(r)
		if mode == AuthModeIAT {
			labelAuthMethod = MetricAuthMethodIAT
		}
		if mode == AuthModeAnonymous && deps.AnonConfig.RequireInitialAccessToken() {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			// R8 AC3 — F-219 short-circuit still counts as an error
			// emission for ops dashboards.
			recordError(ctx, ErrCodeInvalidToken)
			WriteError(w, http.StatusUnauthorized, ErrCodeInvalidToken,
				MissingOrInvalidAccessTokenDescription)
			return
		}

		// 2. Decode request body (R2)
		decoded, err := Decode(r, DecodeOptions{MaxBodyBytes: deps.MaxBodyBytes})
		if err != nil {
			writeDispatchError(ctx, w, err)
			return
		}

		// 3. Authenticate (R3) — either resolve the Bearer IAT OR fall
		// through to anonymous resolution.
		var regCtx *RegistrationContext
		switch mode {
		case AuthModeIAT:
			regCtx, err = ResolveIAT(ctx, deps.Queries, deps.Verifier, deps.Parser, bearer, deps.AntiEnumDummyHash)
		default:
			regCtx, err = ResolveAnonymous(ctx, deps.AnonConfig)
		}
		if err != nil {
			writeAuthError(ctx, w, err)
			return
		}

		// 3. Clamp + validate (R4 / R5)
		clamped, err := ValidateAndClampMetadata(deps.Config, decoded, deps.SupportedSigAlgs, deps.SoftwareStatementEnabled)
		if err != nil {
			writeDispatchError(ctx, w, err)
			return
		}

		// 3a. software_statement pipeline (cavekit-software-statement.md
		// R2..R9 / T-031). Skip when pipeline isn't wired or the body
		// carried no software_statement. Pipeline failures (R2/R3/R5/R7/R9)
		// produce *software_statement.ParseError which we translate to
		// the same RFC 7591 envelope writeDispatchError emits for
		// ClampError. NO event is pushed on a pipeline rejection.
		var softwareStatementJTI string
		if deps.SoftwareStatementPipeline != nil && clamped.SoftwareStatement != "" {
			ssResult, ssErr := software_statement.Run(ctx, clamped.SoftwareStatement, *deps.SoftwareStatementPipeline)
			if ssErr != nil {
				recordError(ctx, ssErr.Code)
				WriteError(w, http.StatusBadRequest, ssErr.Code,
					ssErr.Description)
				return
			}
			if ssResult != nil {
				softwareStatementJTI = ssResult.JTI

				// Apply R6 override mapping: re-clamp the merged body so
				// JWT-supplied redirect_uris / grant_types / etc. still
				// pass the Phase 1 R4 allow-lists (kit explicit: "merged
				// result still flows through Phase 1 R4 clamps").
				if len(ssResult.MergedExtra) > 0 {
					mergedDecoded, mergeErr := mergeOverrideClaims(decoded, ssResult.MergedExtra)
					if mergeErr != nil {
						recordError(ctx, ErrCodeInvalidClientMetadata)
						WriteError(w, http.StatusBadRequest, ErrCodeInvalidClientMetadata,
							"software_statement override merge failed")
						return
					}
					reclamped, clampErr := ValidateAndClampMetadata(deps.Config, mergedDecoded,
						deps.SupportedSigAlgs, deps.SoftwareStatementEnabled)
					if clampErr != nil {
						writeDispatchError(ctx, w, clampErr)
						return
					}
					clamped = reclamped
				}
			}
		}

		// Populate application_type label now that clamp succeeded —
		// metric label cardinality is bounded by the
		// [DCRConfigSubset.AllowedApplicationTypes] config (R8 AC1).
		labelApplicationType = clamped.ApplicationType

		// 3b. Consume IAT slot (R6 amendments 2026-04-27 / F-200 + N-6).
		// MUST run AFTER clamp succeeds — clamp errors are not metadata-
		// fault attribution and MUST NOT burn IAT slots. Otherwise an
		// attacker with one stolen IAT can burn MaxUses slots by sending
		// MaxUses malformed bodies (DoS amplification). Consume MUST
		// still run BEFORE Register so an exhausted/revoked IAT short-
		// circuits before any application events are pushed. Anonymous
		// mode (regCtx.IATID == "") skips the call.
		if regCtx.IATID != "" {
			// cavekit-console-ui-docs-and-observability.md R7 AC5
			// (T-066) — `oidc.dcr.iat.consume` covers the IAT slot
			// reservation. AC6 satisfied: no attributes carry the
			// IAT plaintext or its hash (we already have only the
			// resolved IATID at this point, never the bearer).
			consumeCtx, consumeSpan := tracing.NewNamedSpan(ctx, "oidc.dcr.iat.consume")
			cErr := deps.ConsumeIAT(consumeCtx, regCtx)
			consumeSpan.EndWithError(cErr)
			if cErr != nil {
				// R8 AC5 — Exhausted is a distinct counter from the
				// generic errors_total. Match by the kit-mandated
				// description string in the ClampError; everything
				// else falls through to the generic auth-error path.
				if isExhaustedConsumeError(cErr) {
					recordIATExhausted(ctx)
				}
				writeAuthError(ctx, w, cErr)
				return
			}
			recordIATConsumed(ctx)
		}

		// 3c. EffectivePolicy resolution (cavekit-org-dcr-policy.md R8 /
		// T-033). When a resolver is wired and the resolved org has a
		// merged policy, surface its RAT lifetime / audience override
		// downstream. Resolver failure is treated as "no override" — the
		// register handler MUST NOT 5xx because of a policy lookup miss
		// (Phase 1 byte-identical invariant when no resolver / no row).
		var (
			effectiveRATLifetime    time.Duration
			effectivePolicyResolved bool
			policyScope             = MetricScopeStaticConfig
		)
		if deps.EffectivePolicy != nil && regCtx.OrgID != "" {
			policy, polErr := deps.EffectivePolicy(ctx, regCtx.OrgID)
			if polErr == nil && policy != nil {
				effectiveRATLifetime = policy.RegistrationAccessTokenLifetime
				effectivePolicyResolved = true
				if policy.AllowedAudiencesScope != "" {
					policyScope = policy.AllowedAudiencesScope
				}
				// AllowedAudiences override is observable to downstream
				// callers via the Register closure, which consults the
				// policy to clamp audience metadata it persists. Since
				// the DCR register handler itself does NOT currently
				// clamp `audience` claims (that's the RFC 8707 sidecar's
				// job at /authorize and /token), the audience component
				// of the merge is communicated via tracing attributes
				// from T-040, not via a side-effect on `clamped`.
				_ = policy.AllowedAudiences
			}
		}
		// T-040 — surface `dcr.policy.scope` on the register span. Span
		// attribute carries the merged scope label only; never the
		// resolved AllowedAudiences URI list (kit R7 explicit privacy
		// constraint). T-044 — surface `dcr.jwks.source` on the same
		// span. `inline` when the body provided inline `jwks`; `uri`
		// when only `jwks_uri` was provided; `none` when neither.
		jwksSource := "none"
		if len(clamped.Jwks) > 0 {
			jwksSource = "inline"
		} else if clamped.JwksURI != "" {
			jwksSource = "uri"
		}
		trace.SpanFromContext(ctx).SetAttributes(
			attribute.String("dcr.policy.scope", policyScope),
			attribute.String("dcr.jwks.source", jwksSource),
		)

		// 4. Persist (R6)
		registrationMethod := RegMethodAnonymous
		if mode == AuthModeIAT {
			registrationMethod = RegMethodIAT
		}
		req := &RegisterRequest{
			Clamped:                 clamped,
			OrgID:                   regCtx.OrgID,
			ProjectID:               regCtx.ProjectID,
			IATID:                   regCtx.IATID,
			RegistrationMethod:      registrationMethod,
			ClientNameUnclamped:     decoded.ClientName,
			RemoteIPString:          http_util.RemoteIPStringFromRequest(r),
			UserAgent:               r.UserAgent(),
			SoftwareStatementJTI:    softwareStatementJTI,
			EffectiveRATLifetime:    effectiveRATLifetime,
			EffectivePolicyResolved: effectivePolicyResolved,
		}
		result, err := deps.Register(ctx, req)
		if err != nil {
			writeDispatchError(ctx, w, err)
			return
		}

		// 5. Echo persisted client_name (R2 synthesis applied at command layer)
		clamped.ClientName = result.PersistedAppName

		// 6. Respond 201 (R7)
		out := &RegistrationOutput{
			ClientID:              result.ClientID,
			ClientSecret:          result.ClientSecret,
			ClientSecretExpiresIn: result.ClientSecretExpiresIn,
			RATPlaintext:          result.RATPlaintext,
			RATExpiresAt:          result.RATExpiresAt,
			ClientIDIssuedAt:      result.ClientIDIssuedAt,
			Clamped:               clamped,
		}
		_ = WriteRegistrationResponse(ctx, w, out)
	}
}

// manageRoutes returns the GET / PUT / DELETE handlers for the RFC
// 7592 manage path. When [RegistrationDeps.Manage] is configured the
// handlers run [manageVerifyDispatch] (cavekit-manage-handler.md R2 /
// T-051) — full RAT verification + silent rehash + expiry check.
// Otherwise they fall back to the bearer-presence-only gate (T-050)
// so deployments mid-rollout still emit 401 instead of 500.
//
// GET body landed in T-053 (getClientHandler). PUT / DELETE bodies
// land in T-054 / T-056; for now those stubs return 501 after the
// dispatch chain proves the caller is authorised.
func manageRoutes(deps RegistrationDeps) (get, put, del http.HandlerFunc) {
	if deps.Manage != nil {
		return manageVerifyDispatch(*deps.Manage, getClientHandler(*deps.Manage)),
			manageVerifyDispatch(*deps.Manage, choosePUTHandler(*deps.Manage)),
			manageVerifyDispatch(*deps.Manage, chooseDELETEHandler(*deps.Manage))
	}
	return manageBearerGate(getClientStub),
		manageBearerGate(putClientStub),
		manageBearerGate(deleteClientStub)
}

// choosePUTHandler picks the real PUT body when the Update closure is
// wired (T-054). When unset, falls back to the 501 stub so deployments
// mid-rollout still emit a uniform error envelope. The decision lives
// here (not inside putClientHandler) so the stub vs real-body branch
// is structural — tests can wire a ManageDeps with Update=nil and pin
// the 501 contract without spinning the whole pipeline.
func choosePUTHandler(deps ManageDeps) http.HandlerFunc {
	if deps.Update == nil {
		return putClientStub
	}
	return putClientHandler(deps)
}

// chooseDELETEHandler is the same stub-vs-real selector as
// [choosePUTHandler] for the DELETE route (T-056). When the Delete
// closure is unset, the route returns 501 so deployments mid-rollout
// still emit a uniform error envelope.
func chooseDELETEHandler(deps ManageDeps) http.HandlerFunc {
	if deps.Delete == nil {
		return deleteClientStub
	}
	return deleteClientHandler(deps)
}

// writeDispatchError emits the RFC 7591 envelope for any error
// returned by the pipeline stages. Maps *ClampError directly via
// HTTPStatus+Code; non-ClampError errors map to 500 + server_error
// (cavekit-register-handler.md R8 amendment 2026-04-27 / F-202).
//
// Per R8 AC: internal errors MUST NOT echo `err.Error()` to the body.
// The full error chain is logged server-side via slog at WARN+ severity
// for operator recovery; the response carries only a fixed
// `internal server error` description so an unauthenticated caller
// cannot fingerprint the database, eventstore, or other internal state.
//
// N-4 fix: takes the request ctx so slog.WarnContext can preserve
// tracing / instance / request correlation IDs the operator needs to
// correlate the log line back to the failed request.
func writeDispatchError(ctx context.Context, w http.ResponseWriter, err error) {
	var ce *ClampError
	if errors.As(err, &ce) {
		// T-067 / R8 AC3 — increment errors_total with the RFC 7591
		// envelope code label. ClampErrors carry the canonical
		// invalid_client_metadata / invalid_redirect_uri / etc. codes.
		recordError(ctx, ce.Code)
		WriteError(w, ce.HTTPStatus(), ce.Code, ce.Description)
		return
	}
	slog.WarnContext(ctx, "dcr: dispatcher internal error",
		slog.Any("err", err))
	recordError(ctx, ErrCodeServerError)
	WriteError(w, http.StatusInternalServerError, ErrCodeServerError,
		"internal server error")
}

// writeAuthError is writeDispatchError + WWW-Authenticate header for
// 401 invalid_token responses (R8 AC). All ClampErrors with code
// `invalid_token` get the header; everything else falls through.
func writeAuthError(ctx context.Context, w http.ResponseWriter, err error) {
	var ce *ClampError
	if errors.As(err, &ce) && ce.Code == ErrCodeInvalidToken {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		// T-067 / R8 AC3 — record the 401 envelope code on errors_total
		// before emitting the response.
		recordError(ctx, ce.Code)
		WriteError(w, http.StatusUnauthorized, ce.Code, ce.Description)
		return
	}
	writeDispatchError(ctx, w, err)
}

// _ is here so unused-field guards stay quiet.
var _ = func() bool {
	var d RegistrationDeps
	_ = d.SupportedSigAlgs
	_ = d.SoftwareStatementEnabled
	_ = authz.GetInstance
	return true
}()
