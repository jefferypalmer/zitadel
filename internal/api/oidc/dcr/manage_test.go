package dcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeManageQueries lets the verify-path tests stub the projection-read
// without spinning up the DB harness. err overrides row when set.
type fakeManageQueries struct {
	row *ManageRATRow
	err error
}

func (f *fakeManageQueries) DCRRATLookupByClientID(_ context.Context, _ string) (*ManageRATRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.row, nil
}

// fakeRATVerifier captures (encoded, presented) per call and returns
// programmable (updated, err). Tracks the call sequence so dummy-Verify
// vs real-Verify can be distinguished structurally.
type fakeRATVerifier struct {
	calls   []verifyCall
	respond func(encoded, presented string) (string, error)
}

type verifyCall struct{ encoded, presented string }

func (f *fakeRATVerifier) Verify(encoded, presented string) (string, error) {
	f.calls = append(f.calls, verifyCall{encoded, presented})
	if f.respond == nil {
		return "", nil
	}
	return f.respond(encoded, presented)
}

// fakeRehasher captures the (projectID, orgID, appID, hash) tuple.
type fakeRehasher struct {
	calls []rehashCall
	err   error
}

type rehashCall struct{ projectID, orgID, appID, hash string }

func (f *fakeRehasher) fn(_ context.Context, projectID, orgID, appID, hash string) error {
	f.calls = append(f.calls, rehashCall{projectID, orgID, appID, hash})
	return f.err
}

func newDeps(q ManageQueries, v RATVerifier, r Rehasher, dummy string) ManageDeps {
	return ManageDeps{
		Queries: q, RATVerifier: v, Rehasher: r,
		AntiEnumDummyHash: dummy,
	}
}

// TestVerifyRAT_Success covers the happy path — known client_id +
// matching RAT → returns ManageContext with no rehash + no error.
func TestVerifyRAT_Success(t *testing.T) {
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$argon2id$stored",
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{} // returns ("", nil) — verify ok, no rehash
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	mctx, err := VerifyRAT(context.Background(), deps, "client-1", "zdrat_xxx")
	require.NoError(t, err)
	require.NotNil(t, mctx)
	assert.Equal(t, "client-1", mctx.ClientID)
	assert.Equal(t, "app-1", mctx.AppID)
	assert.Equal(t, "proj-1", mctx.ProjectID)
	assert.Equal(t, "org-1", mctx.ResourceOwner)
	assert.False(t, mctx.Rehashed)

	require.Len(t, v.calls, 1, "happy path must call Verify exactly once (no dummy)")
	assert.Equal(t, "$argon2id$stored", v.calls[0].encoded)
	assert.Equal(t, "zdrat_xxx", v.calls[0].presented)
	assert.Empty(t, r.calls, "no rehash when updatedHash is empty")
}

// TestVerifyRAT_NotFound covers cavekit-manage-handler.md R3 (T-052)
// timing-equivalence prerequisite — when the projection has no row for
// the client_id, VerifyRAT pays one Verify cost against the
// AntiEnumDummyHash, then returns 401 invalid_token. The dispatcher
// (writeAuthError) attaches the WWW-Authenticate header.
func TestVerifyRAT_NotFound(t *testing.T) {
	q := &fakeManageQueries{err: errors.New("not found")}
	v := &fakeRATVerifier{}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	mctx, err := VerifyRAT(context.Background(), deps, "unknown", "zdrat_xxx")
	require.Nil(t, mctx)
	require.Error(t, err)

	var ce *ClampError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Equal(t, http.StatusUnauthorized, ce.HTTPStatus())

	require.Len(t, v.calls, 1, "NotFound branch must pay one dummy-Verify cost")
	assert.Equal(t, "$argon2id$dummy", v.calls[0].encoded,
		"dummy-Verify must use AntiEnumDummyHash so timing matches the real-Verify branch")
}

// TestVerifyRAT_WrongRAT — known client_id but Passwap.Verify rejects
// the presented bearer → 401 invalid_token, no dummy-Verify (the real
// Verify already paid the cost), no rehash.
func TestVerifyRAT_WrongRAT(t *testing.T) {
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$argon2id$stored",
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{
		respond: func(_, _ string) (string, error) { return "", errors.New("hash mismatch") },
	}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	mctx, err := VerifyRAT(context.Background(), deps, "client-1", "zdrat_wrong")
	require.Nil(t, mctx)
	var ce *ClampError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)

	require.Len(t, v.calls, 1, "wrong-RAT branch must NOT additionally call dummy-Verify")
	assert.Equal(t, "$argon2id$stored", v.calls[0].encoded,
		"the single Verify call must be against the stored hash, not dummy")
	assert.Empty(t, r.calls)
}

// TestVerifyRAT_SilentRehash covers cavekit-manage-handler.md R2 AC2 —
// when Passwap returns a non-empty updatedHash (algorithm rotated since
// the RAT was stored), VerifyRAT MUST push the rehashed event scoped
// to (project, org, app) and report Rehashed=true on the ManageContext.
func TestVerifyRAT_SilentRehash(t *testing.T) {
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$bcrypt$stored",
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{
		respond: func(encoded, presented string) (string, error) {
			return "$argon2id$updated", nil
		},
	}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	mctx, err := VerifyRAT(context.Background(), deps, "client-1", "zdrat_xxx")
	require.NoError(t, err)
	require.NotNil(t, mctx)
	assert.True(t, mctx.Rehashed, "silent rehash must set the flag")

	require.Len(t, r.calls, 1, "rehash event must be pushed exactly once")
	c := r.calls[0]
	assert.Equal(t, "proj-1", c.projectID, "rehash routes to the row's project")
	assert.Equal(t, "org-1", c.orgID, "rehash routes to the project's resource owner")
	assert.Equal(t, "app-1", c.appID)
	assert.Equal(t, "$argon2id$updated", c.hash, "must persist the updatedHash from Verify")
}

// TestVerifyRAT_RehashFailureDoesNotFailVerification — the silent-rehash
// push is best-effort; a failure to persist the rotated hash MUST NOT
// invalidate the verification (operator gets the rotation on the next
// verify). The Rehashed flag stays false so callers can distinguish.
func TestVerifyRAT_RehashFailureDoesNotFailVerification(t *testing.T) {
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$bcrypt$stored",
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{
		respond: func(_, _ string) (string, error) { return "$argon2id$updated", nil },
	}
	r := &fakeRehasher{err: errors.New("eventstore push failed")}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	mctx, err := VerifyRAT(context.Background(), deps, "client-1", "zdrat_xxx")
	require.NoError(t, err, "rehash failure does NOT fail verification")
	require.NotNil(t, mctx)
	assert.False(t, mctx.Rehashed, "Rehashed flag stays false when push errored")
}

// TestVerifyRAT_Expired — Lifetime > 0 produced a non-nil ExpiresAt;
// when now > expires, VerifyRAT returns 401 invalid_token. Verify is
// still called (so timing matches the wrong-RAT branch); the expiry
// check runs AFTER verification so a wrong-and-expired RAT still
// looks like a wrong-RAT response (no expiry-vs-wrong oracle).
func TestVerifyRAT_Expired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$argon2id$stored",
		ExpiresAt: &past,
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{} // verify ok
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	_, err := VerifyRAT(context.Background(), deps, "client-1", "zdrat_xxx")
	var ce *ClampError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code, "expired → invalid_token (NOT expired_token)")
	require.Len(t, v.calls, 1, "expired branch still pays Verify cost (post-verify check)")
}

// TestVerifyRAT_FutureExpiryAccepted — ExpiresAt in the future means
// the RAT is still valid; VerifyRAT returns the ManageContext.
func TestVerifyRAT_FutureExpiryAccepted(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$argon2id$stored",
		ExpiresAt: &future,
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	mctx, err := VerifyRAT(context.Background(), deps, "client-1", "zdrat_xxx")
	require.NoError(t, err)
	assert.Equal(t, "app-1", mctx.AppID)
}

// TestManageDeps_Validate enforces every required field. A missing
// field MUST surface at boot (NewHandler panics on Validate failure)
// rather than 5xxing for the lifetime of the process.
func TestManageDeps_Validate(t *testing.T) {
	good := newDeps(&fakeManageQueries{}, &fakeRATVerifier{}, (&fakeRehasher{}).fn, "dummy")
	require.NoError(t, good.Validate())

	type mut func(*ManageDeps)
	cases := []struct {
		name    string
		mutate  mut
		wantErr string
	}{
		{"missing Queries", func(d *ManageDeps) { d.Queries = nil }, "Queries"},
		{"missing RATVerifier", func(d *ManageDeps) { d.RATVerifier = nil }, "RATVerifier"},
		{"missing Rehasher", func(d *ManageDeps) { d.Rehasher = nil }, "Rehasher"},
		{"missing AntiEnumDummyHash", func(d *ManageDeps) { d.AntiEnumDummyHash = "" }, "AntiEnumDummyHash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := good
			tc.mutate(&d)
			err := d.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestManageVerifyDispatch_HappyPath_DelegatesToStub — when verify
// succeeds, the dispatch passes through to the supplied next handler
// with a request ctx carrying the resolved ManageContext. The current
// stubs emit 501; once T-053/T-054/T-056 land they read ManageContext
// from the ctx via [ManageFromContext].
func TestManageVerifyDispatch_HappyPath_DelegatesToStub(t *testing.T) {
	row := &ManageRATRow{
		AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
		TokenHash: "$argon2id$stored",
	}
	q := &fakeManageQueries{row: row}
	v := &fakeRATVerifier{}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	var seen *ManageContext
	probe := func(w http.ResponseWriter, req *http.Request) {
		seen = ManageFromContext(req.Context())
		w.WriteHeader(http.StatusNoContent)
	}
	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, probe)).Methods(http.MethodGet)

	req := httptest.NewRequest(http.MethodGet, "/client-1", nil)
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, seen, "stub must receive ManageContext on ctx")
	assert.Equal(t, "client-1", seen.ClientID)
	assert.Equal(t, "app-1", seen.AppID)
}

// TestManageVerifyDispatch_MissingBearer — no Authorization header →
// 401 + WWW-Authenticate, no Verify call (short-circuit before lookup).
func TestManageVerifyDispatch_MissingBearer(t *testing.T) {
	q := &fakeManageQueries{}
	v := &fakeRATVerifier{}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, getClientStub)).Methods(http.MethodGet)

	req := httptest.NewRequest(http.MethodGet, "/client-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
	assert.Empty(t, v.calls, "missing-Bearer must short-circuit before Verify")
}

// TestManageVerifyDispatch_NotFound_401 — verify-then-401 path emits
// the WWW-Authenticate header (writeAuthError sets it for invalid_token).
func TestManageVerifyDispatch_NotFound_401(t *testing.T) {
	q := &fakeManageQueries{err: errors.New("not found")}
	v := &fakeRATVerifier{}
	r := &fakeRehasher{}
	deps := newDeps(q, v, r.fn, "$argon2id$dummy")

	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, getClientStub)).Methods(http.MethodGet)

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
	assert.Contains(t, rec.Body.String(), `"error":"invalid_token"`)
	assert.Len(t, v.calls, 1, "NotFound branch pays the dummy-Verify cost")
}
