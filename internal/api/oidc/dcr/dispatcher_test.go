package dcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
