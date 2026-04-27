package dcr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// T-066 — OpenTelemetry spans for DCR operations
// (cavekit-console-ui-docs-and-observability.md R7).
//
// Pins all six R7 acceptance criteria:
//
//   - AC1 `oidc.dcr.register` on POST.
//   - AC2 `oidc.dcr.read`     on GET.
//   - AC3 `oidc.dcr.update`   on PUT.
//   - AC4 `oidc.dcr.delete`   on DELETE.
//   - AC5 `oidc.dcr.iat.consume` on every IAT consumption.
//   - AC6 span attributes never carry `client_secret`,
//         `registration_access_token`, IAT plaintext, or
//         `software_statement` content.
//
// Test plumbing: an in-memory tracetest.SpanRecorder is registered as
// the global TracerProvider's span processor in `init()`. The
// `backend/v3/instrumentation/tracing` package caches the resolved
// tracer at first-use via sync.OnceValue, so the global swap MUST
// happen BEFORE the first NewNamedSpan call — `init()` is the only
// hook that runs early enough.

var dcrSpanRecorder *tracetest.SpanRecorder

func init() {
	dcrSpanRecorder = tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(dcrSpanRecorder))
	otel.SetTracerProvider(tp)
}

func resetDCRSpans(t *testing.T) {
	t.Helper()
	dcrSpanRecorder.Reset()
}

func dcrSpanNames(spans []sdktrace.ReadOnlySpan) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Name())
	}
	return out
}

// forbiddenAttrSubstrings is the AC6 deny-list. We compare against the
// attribute KEY (lowercased) — the only knob owned by this code. The
// test deliberately covers all four kit-named values plus their
// common synonyms.
var forbiddenAttrSubstrings = []string{
	"client_secret", "registration_access_token", "rat",
	"iat_token", "iat_plaintext", "software_statement",
}

func assertNoSecretSpanAttrs(t *testing.T, spans []sdktrace.ReadOnlySpan) {
	t.Helper()
	for _, s := range spans {
		for _, kv := range s.Attributes() {
			key := strings.ToLower(string(kv.Key))
			for _, banned := range forbiddenAttrSubstrings {
				if strings.Contains(key, banned) {
					t.Fatalf("R7 AC6 violation: span %q attribute key %q contains forbidden substring %q",
						s.Name(), kv.Key, banned)
				}
			}
		}
	}
}

// TestT066_R7_AC1_RegisterSpanEmitted pins R7 AC1 — POST emits
// `oidc.dcr.register`.
func TestT066_R7_AC1_RegisterSpanEmitted(t *testing.T) {
	resetDCRSpans(t)

	register := &stubRegister{clientID: "client-abc"}
	h := newDispatchHandler(t, register.fn(),
		stubAnonConfig{defaultOrgID: "org-1", defaultProject: "proj-1"})

	body := `{
		"client_name": "OTel Smoke",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))
	require.Equal(t, http.StatusCreated, w.Code, "201 happy-path required")

	spans := dcrSpanRecorder.Ended()
	assert.Contains(t, dcrSpanNames(spans), "oidc.dcr.register",
		"R7 AC1: oidc.dcr.register span MUST be emitted on POST")
	assertNoSecretSpanAttrs(t, spans)
}

// TestT066_R7_AC2_ReadSpanEmitted pins R7 AC2 — GET emits
// `oidc.dcr.read`.
func TestT066_R7_AC2_ReadSpanEmitted(t *testing.T) {
	resetDCRSpans(t)

	meta := &ManageMetaRow{
		AppID:            "app-1",
		ClientName:       "OTel",
		ClientIDIssuedAt: fixedIssued,
		RedirectURIs:     []string{"https://example.com/cb"},
		GrantTypes:       []string{"authorization_code"},
		ResponseTypes:    []string{"code"},
		ApplicationType:  "web",
		AuthMethodType:   "none",
	}
	rec := serveGET(newGETDeps(meta, nil), "client-1")
	require.Equal(t, http.StatusOK, rec.Code)

	spans := dcrSpanRecorder.Ended()
	assert.Contains(t, dcrSpanNames(spans), "oidc.dcr.read",
		"R7 AC2: oidc.dcr.read span MUST be emitted on GET")
	assertNoSecretSpanAttrs(t, spans)
}

// TestT066_R7_AC3_UpdateSpanEmitted pins R7 AC3 — PUT emits
// `oidc.dcr.update`.
func TestT066_R7_AC3_UpdateSpanEmitted(t *testing.T) {
	resetDCRSpans(t)

	rec := servePUT_T066(t)
	require.Equal(t, http.StatusOK, rec.Code, "PUT happy-path required")

	spans := dcrSpanRecorder.Ended()
	assert.Contains(t, dcrSpanNames(spans), "oidc.dcr.update",
		"R7 AC3: oidc.dcr.update span MUST be emitted on PUT")
	assertNoSecretSpanAttrs(t, spans)
}

// TestT066_R7_AC4_DeleteSpanEmitted pins R7 AC4 — DELETE emits
// `oidc.dcr.delete`.
func TestT066_R7_AC4_DeleteSpanEmitted(t *testing.T) {
	resetDCRSpans(t)

	d := &fakeDelete{revoked: 0}
	deps := newDELETEDeps(d)
	rec := serveDELETE(deps, "client-1")
	require.Equal(t, http.StatusNoContent, rec.Code, "DELETE happy-path required")

	spans := dcrSpanRecorder.Ended()
	assert.Contains(t, dcrSpanNames(spans), "oidc.dcr.delete",
		"R7 AC4: oidc.dcr.delete span MUST be emitted on DELETE")
	assertNoSecretSpanAttrs(t, spans)
}

// TestT066_R7_AC5_IATConsumeSpanEmitted pins R7 AC5 — every IAT
// consumption emits `oidc.dcr.iat.consume`. This test exercises the
// dispatcher in IAT mode end-to-end so the consume call site is
// reached through the production code path, not via direct
// invocation. AC1 (oidc.dcr.register) is asserted as a side-effect
// since both spans fire on the same request.
func TestT066_R7_AC5_IATConsumeSpanEmitted(t *testing.T) {
	resetDCRSpans(t)

	hasher := mustBuildHasher(t)
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)
	encodedHash, err := hasher.Hash("zdiat_id1.random")
	require.NoError(t, err)

	consumeCalls := 0
	deps := RegistrationDeps{
		Queries: stubQueries{row: &QueryIATRow{
			ID: "id1", InstanceID: "test-instance", ResourceOwner: "ro-1",
			ProjectID: "proj-1", TokenHash: encodedHash,
		}},
		Verifier:          bcryptVerifier{Swapper: hasher.(bcryptHasher).Swapper},
		Parser:            stubParser,
		Config:            defaultStubConfig(),
		AnonConfig:        stubAnonConfig{defaultOrgID: "o", defaultProject: "p"},
		SupportedSigAlgs:  []string{"RS256"},
		AntiEnumDummyHash: dummy,
		Register:          (&stubRegister{clientID: "client-iat"}).fn(),
		MaxBodyBytes:      64 * 1024,
		ConsumeIAT: func(_ context.Context, _ *RegistrationContext) error {
			consumeCalls++
			return nil
		},
	}
	h := NewHandler(deps)

	body := `{
		"client_name": "IAT Span Probe",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer zdiat_id1.random")
	req = req.WithContext(ctxWithFeature(t, true))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code,
		"IAT-mode 201 happy-path required to reach the consume call")
	require.Equal(t, 1, consumeCalls,
		"sanity: ConsumeIAT MUST be invoked once on success path")

	names := dcrSpanNames(dcrSpanRecorder.Ended())
	assert.Contains(t, names, "oidc.dcr.register",
		"R7 AC1 side-check: register span emitted on IAT-mode POST")
	assert.Contains(t, names, "oidc.dcr.iat.consume",
		"R7 AC5: oidc.dcr.iat.consume MUST wrap the IAT slot reservation")
	assertNoSecretSpanAttrs(t, dcrSpanRecorder.Ended())
}

// TestT066_R7_AC6_NoSecretAttributes_AcrossAllOps is the cross-handler
// pin for AC6 — runs every DCR span-emitting op in sequence (POST,
// GET, PUT, DELETE) and asserts no span carries a forbidden attribute
// key. Backstop in case a future code change adds attribute calls.
func TestT066_R7_AC6_NoSecretAttributes_AcrossAllOps(t *testing.T) {
	resetDCRSpans(t)

	// POST
	register := &stubRegister{clientID: "secrets-probe"}
	hPost := newDispatchHandler(t, register.fn(),
		stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})
	postBody := `{
		"client_name": "secrets-probe",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	hPost.ServeHTTP(httptest.NewRecorder(), newJSONPostReq(t, postBody))

	// GET
	meta := &ManageMetaRow{
		AppID: "app-1", ClientName: "x",
		ClientIDIssuedAt: fixedIssued,
		RedirectURIs:     []string{"https://example.com/cb"},
		GrantTypes:       []string{"authorization_code"},
		ResponseTypes:    []string{"code"},
		ApplicationType:  "web",
		AuthMethodType:   "none",
	}
	_ = serveGET(newGETDeps(meta, nil), "client-1")

	// PUT
	_ = servePUT_T066(t)

	// DELETE
	_ = serveDELETE(newDELETEDeps(&fakeDelete{}), "client-1")

	spans := dcrSpanRecorder.Ended()
	require.NotEmpty(t, spans, "fixture sanity: at least one span MUST land")
	assertNoSecretSpanAttrs(t, spans)
}

// servePUT_T066 mints a minimal happy-path PUT request carrying a
// Bearer header and returns the recorder. Decoupled from the existing
// PUT tests so this file's spans stay isolated from any state leaking
// across packages.
func servePUT_T066(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()

	updateFn := func(_ context.Context, _ *UpdateRequest) (*UpdateResult, error) {
		return &UpdateResult{}, nil
	}
	deps := ManageDeps{
		Queries: &fakeManageQueries{
			row: &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			},
		},
		RATVerifier:              &fakeRATVerifier{},
		Rehasher:                 (&fakeRehasher{}).fn,
		AntiEnumDummyHash:        "$argon2id$dummy",
		Update:                   updateFn,
		Config:                   defaultStubConfig(),
		SupportedSigAlgs:         []string{"RS256"},
		SoftwareStatementEnabled: false,
		MaxBodyBytes:             64 * 1024,
	}

	body := `{
		"client_name": "OTel PUT",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	router := newPUTRouter_T066(deps)
	req := httptest.NewRequest(http.MethodPut, "/client-1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// newPUTRouter_T066 mounts the PUT handler under /{client_id} on a
// fresh mux router so the test does not share state with the wider
// NewHandler wiring (which also wires POST + GET + DELETE).
func newPUTRouter_T066(deps ManageDeps) http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/{client_id}", manageVerifyDispatch(deps, putClientHandler(deps))).Methods(http.MethodPut)
	return r
}
