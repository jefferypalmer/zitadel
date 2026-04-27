package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManage_AntiEnum_R3 covers cavekit-manage-handler.md R3 (T-052)
// across all three RFC 7592 verbs uniformly:
//
//  AC1: unknown client_id → 401 (NOT 404).
//  AC2: handler calls passwap.Verify against the dummy hash so the
//       unknown-client_id branch pays the same Verify cost as the
//       wrong-RAT branch — timing equivalence prerequisite for
//       T-058's structural side-channel test.
//  AC3: every 401 path (unknown client_id, wrong RAT, missing header)
//       carries `WWW-Authenticate: Bearer error="invalid_token"`.
//
// The R3 implementation lives in [VerifyRAT]'s NotFound branch
// (manage.go) — T-051 wired it. This file is the cross-handler
// pinning that ensures GET, PUT, and DELETE all behave uniformly so
// a future task that bypasses VerifyRAT for one verb can't
// regress only that verb's anti-enum posture without a test
// failure.
func TestManage_AntiEnum_R3(t *testing.T) {
	verbs := []struct {
		method string
		// Each verb exercises the same dispatch chain, but the
		// downstream stub differs (GET → getClientHandler, PUT/DELETE
		// → 501 stubs). Anti-enum is enforced before the stub runs,
		// so the stub identity is irrelevant to the test.
		next http.HandlerFunc
	}{
		{http.MethodGet, getClientStub},
		{http.MethodPut, putClientStub},
		{http.MethodDelete, deleteClientStub},
	}

	for _, v := range verbs {
		t.Run(v.method+"_unknown_client_id", func(t *testing.T) {
			q := &fakeManageQueries{err: errors.New("not found")}
			vr := &fakeRATVerifier{}
			rh := &fakeRehasher{}
			deps := newDeps(q, vr, rh.fn, "$argon2id$dummy")

			router := mux.NewRouter()
			router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, v.next)).Methods(v.method)
			req := httptest.NewRequest(v.method, "/never-existed", nil)
			req.Header.Set("Authorization", "Bearer zdrat_xxx")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			// AC1: 401 not 404.
			require.Equal(t, http.StatusUnauthorized, rec.Code,
				"%s on unknown client_id MUST return 401 — leaking 404 enables enumeration", v.method)

			// AC3: WWW-Authenticate present with the canonical RFC 6750 form.
			assert.Equal(t, `Bearer error="invalid_token"`,
				rec.Header().Get("WWW-Authenticate"),
				"%s 401 missing WWW-Authenticate header", v.method)

			// Body shape: invalid_token envelope.
			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, "invalid_token", body["error"])
			assert.Equal(t, MissingOrInvalidAccessTokenDescription, body["error_description"])

			// AC2: dummy-Verify was called with the AntiEnumDummyHash —
			// proves the unknown-client_id branch pays one Verify cost
			// matching what wrong-RAT pays. Timing-distinguishability
			// (the actual nanosecond-level proof) is T-058's job; this
			// test pins the structural prerequisite.
			require.Len(t, vr.calls, 1,
				"%s NotFound branch MUST call dummy-Verify exactly once", v.method)
			assert.Equal(t, "$argon2id$dummy", vr.calls[0].encoded,
				"%s dummy-Verify must use AntiEnumDummyHash, not the row hash", v.method)
		})

		t.Run(v.method+"_wrong_RAT", func(t *testing.T) {
			// AC3: known client_id + wrong RAT also returns 401 +
			// WWW-Authenticate. Symmetric to the unknown-client_id case
			// per the kit ("All 401 responses ... missing header,
			// wrong RAT, unknown client_id").
			row := &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			}
			q := &fakeManageQueries{row: row}
			vr := &fakeRATVerifier{
				respond: func(_, _ string) (string, error) { return "", errors.New("hash mismatch") },
			}
			rh := &fakeRehasher{}
			deps := newDeps(q, vr, rh.fn, "$argon2id$dummy")

			router := mux.NewRouter()
			router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, v.next)).Methods(v.method)
			req := httptest.NewRequest(v.method, "/client-1", nil)
			req.Header.Set("Authorization", "Bearer zdrat_wrong")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, `Bearer error="invalid_token"`,
				rec.Header().Get("WWW-Authenticate"))
		})

		t.Run(v.method+"_missing_header", func(t *testing.T) {
			// AC3: missing Authorization header → 401 + WWW-Authenticate
			// (this is also covered by T-050's TestHandler_ManageBearerGate
			// but kept here so a future refactor that splits anti-enum
			// from bearer-gate keeps both behaviors paired in one test
			// file).
			deps := newDeps(&fakeManageQueries{}, &fakeRATVerifier{}, (&fakeRehasher{}).fn, "$argon2id$dummy")
			router := mux.NewRouter()
			router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, v.next)).Methods(v.method)
			req := httptest.NewRequest(v.method, "/client-1", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, `Bearer error="invalid_token"`,
				rec.Header().Get("WWW-Authenticate"))
		})
	}
}

// TestManage_AntiEnum_DummyHashSourceContract pins R3 AC2's hidden
// prerequisite: the AntiEnumDummyHash MUST come from the same
// configured Passwap Swapper that hashes real RATs (otherwise the
// algorithm prefix mismatch reproduces F-101 — verifier returns
// ErrNoVerifier in microseconds while real-RAT verify takes
// milliseconds, inverting the timing oracle).
//
// The structural defence is [BuildAntiEnumDummyHash]'s startup
// probe. This test exercises the contract: ManageDeps.Validate
// rejects empty AntiEnumDummyHash so a wiring that forgets to
// populate it cannot reach traffic.
func TestManage_AntiEnum_DummyHashSourceContract(t *testing.T) {
	deps := ManageDeps{
		Queries:     &fakeManageQueries{},
		RATVerifier: &fakeRATVerifier{},
		Rehasher:    (&fakeRehasher{}).fn,
		// AntiEnumDummyHash deliberately empty — boot must refuse.
	}
	err := deps.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AntiEnumDummyHash",
		"empty AntiEnumDummyHash must surface at boot — F-101 lesson")
}

// TestManage_AntiEnum_NoCacheOn401 pins that anti-enum 401 responses
// stay no-store / no-cache (cavekit-security-hardening.md T14
// crossref). A CDN that pinned a 401 for client_id=X would keep the
// response after the operator legitimately registered X — turning a
// transient 401 into a permanent enumeration signal.
func TestManage_AntiEnum_NoCacheOn401(t *testing.T) {
	q := &fakeManageQueries{err: errors.New("not found")}
	deps := newDeps(q, &fakeRATVerifier{}, (&fakeRehasher{}).fn, "$argon2id$dummy")
	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, getClientStub)).Methods(http.MethodGet)
	req := httptest.NewRequest(http.MethodGet, "/never", nil)
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

// _ pulls in context to keep the import list stable when future
// anti-enum tests need ctx.
var _ = context.Background
