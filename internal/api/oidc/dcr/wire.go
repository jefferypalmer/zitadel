package dcr

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zitadel/passwap"

	"github.com/zitadel/zitadel/internal/api/authz"
)

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

	// AntiEnumDummyHash is the precomputed dummy Passwap hash used
	// by [ResolveIAT] for timing equivalence between known-and-wrong
	// and unknown branches. MUST be built via [BuildAntiEnumDummyHash]
	// at startup; passing a hand-written literal here violates
	// cavekit-iat.md R4 amendment 2026-04-27 and reintroduces the
	// F-101 inverted-oracle vulnerability.
	AntiEnumDummyHash string
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
	r.StrictSlash(true)
	// POST stub still 200 + "stub" body for parity with T-008
	// integration probes. T-040 RegisterClient lands the real body.
	r.HandleFunc("/", postRegisterStub).Methods(http.MethodPost)
	r.HandleFunc("/{client_id}", getClientStub).Methods(http.MethodGet)
	r.HandleFunc("/{client_id}", putClientStub).Methods(http.MethodPut)
	r.HandleFunc("/{client_id}", deleteClientStub).Methods(http.MethodDelete)
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		WriteError(w, http.StatusMethodNotAllowed, ErrCodeInvalidRequest,
			"this DCR endpoint does not support the requested HTTP method.")
	})
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.NotFound(w, req)
	})
	return featureGateMiddleware(r)
}

// _ is here so deps fields are referenced by Validate; staticcheck
// would otherwise flag unused fields once T-040 wires read-only
// access from inside the handler bodies.
var _ = func() bool {
	var d RegistrationDeps
	_ = d.SupportedSigAlgs
	_ = d.SoftwareStatementEnabled
	_ = authz.GetInstance // anchored import for future inline use
	return true
}()
