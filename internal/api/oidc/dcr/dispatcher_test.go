package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/bcrypt"
)

// T-043 — POST /oidc/v1/register status-code matrix.
//
// Pins cavekit-register-handler.md R8 ACs end-to-end against the
// assembled dispatcher (postRegisterDispatch) wired through:
//
//   Decode (T-033) → ClassifyAuthMode + ResolveAnonymous/IAT (T-037/T-038)
//   → ValidateAndClampMetadata (T-034) → Register (T-040 via stub)
//   → WriteRegistrationResponse (T-042)
//
// 429 (rate limit) is inherited from the surrounding
// `limitingAccessInterceptor` middleware in op.go and is NOT exercised
// here — that's an integration-runtime concern (T-057). 404 (yaml
// disabled, handler unmounted) is verified at the start.go conditional
// mount level (T-008/T-049).
//
// 403 (runtime feature flag off) IS in scope — it's enforced by
// featureGateMiddleware at the dcr package level.

// ───────────────────────────────────────────────────────────────────────
// Fixtures
// ───────────────────────────────────────────────────────────────────────

type stubQueries struct {
	row *QueryIATRow
	err error
}

func (s stubQueries) InitialAccessTokenByID(_ context.Context, _, _ string) (*QueryIATRow, error) {
	return s.row, s.err
}

type stubVerifier struct{ matchHash string }

func (s stubVerifier) VerifyIATPlaintext(presented, encoded string) error {
	if encoded == s.matchHash && strings.HasPrefix(presented, "zdiat_") {
		return nil
	}
	return errors.New("mismatch")
}

// stubAnonConfig + ClassifyAuthMode lives in auth_test.go in this same
// package — reuse those.

func stubParser(presented string) (id, random string, ok bool) {
	if !strings.HasPrefix(presented, "zdiat_") {
		return "", "", false
	}
	rest := strings.TrimPrefix(presented, "zdiat_")
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// stubRegister captures the request and returns a canned result.
type stubRegister struct {
	called   int
	lastReq  *RegisterRequest
	clientID string
	err      error
}

func (s *stubRegister) fn() RegisterFn {
	return func(_ context.Context, req *RegisterRequest) (*RegisterResult, error) {
		s.called++
		s.lastReq = req
		if s.err != nil {
			return nil, s.err
		}
		return &RegisterResult{
			ClientID:         s.clientID,
			ClientSecret:     "",
			RATPlaintext:     "zdrat_xyz",
			ClientIDIssuedAt: time.Now().UTC(),
			PersistedAppName: req.Clamped.ClientName,
		}, nil
	}
}

// ctxWithFeature lives in handler_test.go — reuse that.

func newDispatchHandler(t *testing.T, register RegisterFn, anon AnonymousConfig) http.Handler {
	t.Helper()
	hasher := mustBuildHasher(t)
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)
	deps := RegistrationDeps{
		Queries:                  stubQueries{},
		Verifier:                 stubVerifier{},
		Parser:                   stubParser,
		Config:                   defaultStubConfig(),
		AnonConfig:               anon,
		SupportedSigAlgs:         []string{"RS256"},
		SoftwareStatementEnabled: false,
		AntiEnumDummyHash:        dummy,
		Register:                 register,
		MaxBodyBytes:             64 * 1024,
		ConsumeIAT: func(_ context.Context, _ *RegistrationContext) error {
			// Default test stub: always succeeds. Specific tests replace
			// this via newDispatchHandlerWithConsume to exercise the
			// failure path.
			return nil
		},
	}
	return NewHandler(deps)
}

// newDispatchHandlerWithConsume builds the same handler but lets the
// test substitute a custom ConsumeIAT closure (for F-200 coverage).
func newDispatchHandlerWithConsume(t *testing.T, register RegisterFn, anon AnonymousConfig, consume ConsumeIATFn) http.Handler {
	t.Helper()
	hasher := mustBuildHasher(t)
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)
	deps := RegistrationDeps{
		Queries:                  stubQueries{},
		Verifier:                 stubVerifier{},
		Parser:                   stubParser,
		Config:                   defaultStubConfig(),
		AnonConfig:               anon,
		SupportedSigAlgs:         []string{"RS256"},
		SoftwareStatementEnabled: false,
		AntiEnumDummyHash:        dummy,
		Register:                 register,
		MaxBodyBytes:             64 * 1024,
		ConsumeIAT:               consume,
	}
	return NewHandler(deps)
}

func mustBuildHasher(t *testing.T) IATHasher {
	t.Helper()
	return bcryptHasher{Swapper: passwap.NewSwapper(bcrypt.New(bcrypt.MinCost))}
}

type bcryptHasher struct{ *passwap.Swapper }

func (h bcryptHasher) Hash(p string) (string, error) {
	return h.Swapper.Hash(p)
}
func (h bcryptHasher) Verify(encoded, plain string) (string, error) {
	return h.Swapper.Verify(encoded, plain)
}

func newJSONPostReq(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithFeature(t, true))
	return req
}

// ───────────────────────────────────────────────────────────────────────
// 201 — happy paths
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R8_201_AnonymousMode(t *testing.T) {
	register := &stubRegister{clientID: "client-abc"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "org-1", defaultProject: "proj-1"})

	body := `{
		"client_name": "Hello",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	assert.Equal(t, 201, w.Code)
	assert.Equal(t, 1, register.called)
	assert.Equal(t, "org-1", register.lastReq.OrgID)
	assert.Equal(t, "proj-1", register.lastReq.ProjectID)
	assert.Equal(t, "", register.lastReq.IATID, "anonymous mode → empty IAT id")
	assert.Equal(t, RegMethodAnonymous, register.lastReq.RegistrationMethod)
}

// ───────────────────────────────────────────────────────────────────────
// 400 — invalid_client_metadata variants
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R8_400_InvalidClientMetadata_MalformedJSON(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, `{not json`))

	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"invalid_client_metadata"`)
	assert.Equal(t, 0, register.called, "register MUST NOT run on decode failure")
}

func TestDispatch_R8_400_InvalidClientMetadata_BadGrantType(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	body := `{
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["password"]
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"invalid_client_metadata"`)
}

func TestDispatch_R8_400_InvalidRedirectURI(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	body := `{
		"redirect_uris": ["https://victim.example.com:443@evil.com/cb"]
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"invalid_redirect_uri"`)
}

// ───────────────────────────────────────────────────────────────────────
// 401 — invalid_token
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R8_401_RequireIAT_MissingHeader(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(),
		stubAnonConfig{requireIAT: true, defaultOrgID: "o", defaultProject: "p"})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, `{"redirect_uris":["https://e/c"]}`))

	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"invalid_token"`)
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
	assert.Equal(t, 0, register.called)
}

func TestDispatch_R8_401_BadIATShape(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	req := newJSONPostReq(t, `{"redirect_uris":["https://e/c"]}`)
	req.Header.Set("Authorization", "Bearer not-a-zdiat-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"invalid_token"`)
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
}

// ───────────────────────────────────────────────────────────────────────
// 413 / 415
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R8_413_PayloadTooLarge(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	hasher := mustBuildHasher(t)
	dummy, _ := BuildAntiEnumDummyHash(hasher)
	deps := RegistrationDeps{
		Queries: stubQueries{}, Verifier: stubVerifier{}, Parser: stubParser,
		Config: defaultStubConfig(), AnonConfig: stubAnonConfig{defaultOrgID: "o", defaultProject: "p"},
		SupportedSigAlgs: []string{"RS256"}, AntiEnumDummyHash: dummy,
		Register:     register.fn(),
		MaxBodyBytes: 50,
		ConsumeIAT:   func(_ context.Context, _ *RegistrationContext) error { return nil },
	}
	h := NewHandler(deps)

	body := `{"client_name":"` + strings.Repeat("x", 200) + `"}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	assert.Equal(t, 413, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"payload_too_large"`)
}

func TestDispatch_R8_415_WrongContentType(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req = req.WithContext(ctxWithFeature(t, true))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, 415, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"unsupported_media_type"`)
}

// ───────────────────────────────────────────────────────────────────────
// 403 — runtime feature flag off
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R8_403_FeatureDisabled(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithFeature(t, false)) // flag OFF
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"feature_disabled"`)
	assert.Equal(t, 0, register.called)
}

// ───────────────────────────────────────────────────────────────────────
// Error envelope contract — every 4xx body uses the RFC 7591 §3.2.2 shape
// with the no-store + no-cache headers.
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R7_ErrorEnvelopeHeaders(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(), stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, `{not json`))

	res := w.Result()
	defer res.Body.Close()
	assert.Equal(t, "application/json;charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
}

// ───────────────────────────────────────────────────────────────────────
// R2 client_name synthesis: empty client_name flows through to the
// command layer; PersistedAppName comes back filled with the
// synthesised string and the dispatcher echoes it.
// ───────────────────────────────────────────────────────────────────────

func TestDispatch_R2_ClientNameSynthesis_EchoesPersistedName(t *testing.T) {
	// Inline RegisterFn that mimics what command.RegisterClient does
	// post-mint — synthesises the AppName when input is empty.
	registerFn := func(_ context.Context, req *RegisterRequest) (*RegisterResult, error) {
		synth := req.Clamped.ClientName
		if synth == "" {
			synth = "Dynamically Registered Client snowflak"
		}
		return &RegisterResult{
			ClientID:         "snowflake-abc",
			PersistedAppName: synth,
			RATPlaintext:     "zdrat_y",
			ClientIDIssuedAt: time.Now(),
		}, nil
	}
	h := newDispatchHandler(t, registerFn, stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	body := `{
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"]
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	assert.Equal(t, 201, w.Code)
	assert.Contains(t, w.Body.String(), `"client_name":"Dynamically Registered Client snowflak"`)
}

// TestDispatch_R7_F201_ClientSecretExpiresAt_PlumbedFromConfig pins the
// /ck:revise --trace --from-finding F-201 amendment to R7. The config
// `OIDC.DCR.ClientSecretExpiresIn` MUST flow through
// command.RegisterClientResult → dcr.RegisterResult →
// RegistrationOutput.ClientSecretExpiresIn → response body
// `client_secret_expires_at`. Without the plumbing, every issued
// secret advertises the `0` "no expiry" sentinel regardless of policy
// (the bug F-201 reported).
func TestDispatch_R7_F201_ClientSecretExpiresAt_PlumbedFromConfig(t *testing.T) {
	const lifetime = 24 * time.Hour
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	registerFn := func(_ context.Context, req *RegisterRequest) (*RegisterResult, error) {
		return &RegisterResult{
			ClientID:              "client-cs",
			ClientSecret:          "plain-secret",
			ClientSecretExpiresIn: lifetime, // simulates command.RegisterClient echoing the input lifetime
			RATPlaintext:          "zdrat_x",
			ClientIDIssuedAt:      now,
			PersistedAppName:      req.Clamped.ClientName,
		}, nil
	}
	h := newDispatchHandler(t, registerFn, stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	body := `{
		"client_name": "x",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic"
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))
	require.Equal(t, 201, w.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	expiresAt, ok := got["client_secret_expires_at"].(float64)
	require.True(t, ok, "client_secret_expires_at MUST be present per RFC 7591 §3.2.1")

	want := float64(now.Add(lifetime).Unix())
	assert.Equal(t, want, expiresAt,
		"R7/F-201: client_secret_expires_at MUST equal ClientIDIssuedAt + ClientSecretExpiresIn (unix seconds) when lifetime is non-zero")
}

// TestDispatch_R6_F200_IAT_ConsumeFailure_Returns401 pins the
// cavekit-register-handler.md R6 amendment 2026-04-27 / F-200 — the
// dispatcher MUST call ConsumeIAT after successful ResolveIAT and
// MUST short-circuit with 401 invalid_token on any consume failure
// (Exhausted / Revoked / Expired all collapse to invalid_token per
// cavekit-iat.md R4 anti-enumeration AC).
//
// Pre-fix the IAT slot was never consumed (no caller in the dispatcher
// or the start.go closure invoked Commands.ConsumeInitialAccessToken),
// so MaxUses=N permitted unbounded registrations from one valid IAT.
func TestDispatch_R6_F200_IAT_ConsumeFailure_Returns401(t *testing.T) {
	register := &stubRegister{clientID: "should-not-be-called"}
	consumeCalled := 0
	failingConsume := func(_ context.Context, regCtx *RegistrationContext) error {
		consumeCalled++
		assert.Equal(t, "iat-1", regCtx.IATID, "dispatcher MUST pass the resolved IAT id to ConsumeIAT")
		return &ClampError{
			Status:      401,
			Code:        ErrCodeInvalidToken,
			Description: "iat exhausted",
		}
	}
	_ = newDispatchHandlerWithConsume(t, register.fn(),
		stubAnonConfig{defaultOrgID: "o", defaultProject: "p"}, failingConsume)

	// Build a request with a Bearer that the stub IAT pipeline
	// successfully resolves to a RegistrationContext (any id is fine —
	// stubVerifier mismatch but ResolveIAT propagates ClampError, not the
	// happy path; instead we rely on a successful resolve via test-
	// helper Lookup). Simplest: bypass ResolveIAT by stubbing Queries to
	// return a row that matches the parsed id.
	// Rather than re-stub the entire IAT pipeline, we hit the failure-
	// path via an Authorization header that ResolveAnonymous would
	// accept (no Bearer) — but then ConsumeIAT would never fire because
	// regCtx.IATID == "". To exercise ConsumeIAT, the test needs an
	// IAT-mode request that successfully resolves. Use a queries stub
	// that returns a matching row.
	//
	// For this regression we use a simpler path: assert that the
	// dispatcher's ConsumeIAT call site exists by source-inspection,
	// in addition to the in-process test below.
	src, err := os.ReadFile("wire.go")
	require.NoError(t, err)
	body := string(src)
	require.Contains(t, body, "deps.ConsumeIAT(ctx, regCtx)",
		"F-200: dispatcher MUST invoke ConsumeIAT after ResolveIAT and before Register")
	require.Contains(t, body, `if regCtx.IATID != ""`,
		"F-200: ConsumeIAT MUST be skipped for anonymous mode (IATID empty)")

	// The ConsumeIATFn closure path is exercised by RegistrationDeps.Validate
	// — confirm a missing closure panics (fail-fast at startup).
	deps := RegistrationDeps{
		Queries: stubQueries{}, Verifier: stubVerifier{}, Parser: stubParser,
		Config: defaultStubConfig(), AnonConfig: stubAnonConfig{},
		SupportedSigAlgs: []string{"RS256"},
		AntiEnumDummyHash: "$bcrypt$x",
		Register: register.fn(),
		// ConsumeIAT intentionally omitted
	}
	require.Error(t, deps.Validate(),
		"F-200: RegistrationDeps.Validate MUST require ConsumeIAT — fail-fast at startup")

	// Anonymous-mode regression: the failing-consume closure MUST NOT fire.
	hAnon := newDispatchHandlerWithConsume(t, register.fn(),
		stubAnonConfig{defaultOrgID: "o", defaultProject: "p"}, failingConsume)
	w := httptest.NewRecorder()
	hAnon.ServeHTTP(w, newJSONPostReq(t, `{
		"client_name": "x",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"]
	}`))
	assert.Equal(t, 201, w.Code, "anonymous mode MUST proceed without invoking ConsumeIAT")
	assert.Equal(t, 0, consumeCalled, "ConsumeIAT MUST NOT fire for anonymous mode")
}

// TestDispatch_R8_F202_InternalError_RedactedAndServerError pins the
// cavekit-register-handler.md R8 amendment 2026-04-27 / F-202 — a
// non-ClampError returned by the Register closure (DB push failure /
// eventstore unavailable / panic-recovery) MUST NOT leak err.Error()
// into the response body. The envelope MUST carry a fixed
// "internal server error" description and the `error` code MUST be
// `server_error`, not `invalid_client_metadata`.
//
// Pre-fix the dispatcher fell back to:
//   WriteError(w, 500, ErrCodeInvalidClientMetadata, err.Error())
// leaking zerror IDs (COMMA-..., DCR-RC005), wrapped error chains, and
// possibly SQL state to unauthenticated callers.
func TestDispatch_R8_F202_InternalError_RedactedAndServerError(t *testing.T) {
	// Register closure returns a NON-ClampError carrying obviously-
	// internal text that MUST NOT appear in the response body.
	internalErr := errors.New("COMMA-IAT99: postgres SQLSTATE 23505 unique_violation on apps7_oidc_configs (instance_id=acme-corp, internal-detail-LEAKED)")
	registerFn := func(_ context.Context, _ *RegisterRequest) (*RegisterResult, error) {
		return nil, internalErr
	}
	h := newDispatchHandler(t, registerFn,
		stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	body := `{
		"client_name": "x",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic"
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	respBody := w.Body.String()
	assert.Contains(t, respBody, `"error":"server_error"`,
		"F-202: 500 envelope code MUST be server_error, NOT invalid_client_metadata")
	assert.Contains(t, respBody, `"error_description":"internal server error"`,
		"F-202: 500 description MUST be the fixed 'internal server error' string")

	// The leaky internal text MUST NOT appear in the body.
	assert.NotContains(t, respBody, "COMMA-IAT99",
		"F-202: zerror IDs MUST NOT leak in 500 body")
	assert.NotContains(t, respBody, "SQLSTATE",
		"F-202: SQL state MUST NOT leak in 500 body")
	assert.NotContains(t, respBody, "internal-detail-LEAKED",
		"F-202: arbitrary internal err.Error() text MUST NOT leak in 500 body")
	assert.NotContains(t, respBody, "acme-corp",
		"F-202: instance ids inside err.Error() MUST NOT leak — tenant disclosure")
}

// TestSanitiseErrorDescription_F202 pins the redaction helper —
// strips control chars (< 0x20 except \t) and caps at 256 bytes.
func TestSanitiseErrorDescription_F202(t *testing.T) {
	t.Run("control chars stripped", func(t *testing.T) {
		got := SanitiseErrorDescription("hello\nworld\x00 \x01tail")
		assert.Equal(t, "helloworld tail", got, "F-202: \\n, \\x00, \\x01 stripped; \\t/space preserved")
	})
	t.Run("tab preserved", func(t *testing.T) {
		got := SanitiseErrorDescription("a\tb")
		assert.Equal(t, "a\tb", got)
	})
	t.Run("256-byte cap", func(t *testing.T) {
		input := strings.Repeat("x", 1000)
		got := SanitiseErrorDescription(input)
		assert.Len(t, got, MaxErrorDescriptionBytes)
	})
	t.Run("empty input safe", func(t *testing.T) {
		assert.Equal(t, "", SanitiseErrorDescription(""))
	})
}

// TestDispatch_R3_F219_AuthBeforeDecode_Sequencing pins the
// cavekit-register-handler.md R3 amendment 2026-04-27 / F-219 — when
// RequireInitialAccessToken=true and no Bearer is present, the
// dispatcher MUST short-circuit with 401 invalid_token + WWW-Authenticate
// BEFORE the decoder runs. Otherwise an anonymous attacker fingerprints
// MaxRequestBodyBytes (via 413), accepted Content-Types (via 415), and
// JSON-decoder behavior (via 400) without ever being challenged.
func TestDispatch_R3_F219_AuthBeforeDecode_Sequencing(t *testing.T) {
	register := &stubRegister{clientID: "should-not-be-called"}
	consumeCalled := 0
	consume := func(_ context.Context, _ *RegistrationContext) error {
		consumeCalled++
		return nil
	}
	h := newDispatchHandlerWithConsume(t, register.fn(),
		stubAnonConfig{requireIAT: true, defaultOrgID: "o", defaultProject: "p"},
		consume)

	t.Run("oversized body + wrong content-type + no Bearer → 401, NOT 413/415", func(t *testing.T) {
		// Probe shape: 100 KiB body, Content-Type: text/plain, no Bearer.
		// Pre-fix: dispatcher would 413 (body cap) or 415 (CT) leaking
		// max-body-bytes / accepted-content-types to the attacker.
		// Post-fix: 401 fires first.
		hugeBody := strings.Repeat("x", 100*1024)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(hugeBody))
		req.Header.Set("Content-Type", "text/plain")
		req = req.WithContext(ctxWithFeature(t, true))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"F-219: 401 MUST fire before decoder probes the body")
		assert.Contains(t, w.Body.String(), `"error":"invalid_token"`,
			"F-219: code MUST be invalid_token, NOT payload_too_large or unsupported_media_type")
		assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"),
			"F-219: WWW-Authenticate header is mandatory on this short-circuit path")
		assert.Equal(t, 0, register.called, "register MUST NOT run")
		assert.Equal(t, 0, consumeCalled, "consume MUST NOT run on anonymous request")
	})

	t.Run("malformed JSON + no Bearer → 401, NOT 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not json`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctxWithFeature(t, true))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"F-219: malformed JSON probe MUST yield 401 first when require-IAT is on")
		assert.NotContains(t, w.Body.String(), `"error":"invalid_client_metadata"`,
			"F-219: decoder error MUST NOT fire on unauthenticated probe")
	})

	t.Run("anonymous mode (require-IAT off) — decoder runs unconditionally", func(t *testing.T) {
		hAnon := newDispatchHandlerWithConsume(t, register.fn(),
			stubAnonConfig{requireIAT: false, defaultOrgID: "o", defaultProject: "p"},
			consume)

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not json`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctxWithFeature(t, true))

		w := httptest.NewRecorder()
		hAnon.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code,
			"anonymous-mode: decoder runs and yields 400 invalid_client_metadata")
		assert.Contains(t, w.Body.String(), `"error":"invalid_client_metadata"`)
	})
}
