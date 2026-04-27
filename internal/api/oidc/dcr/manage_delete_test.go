package dcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDelete captures the dispatched DeleteRequest so the tests can
// assert that (a) the handler short-circuits on missing Bearer / wrong
// RAT before calling the command, and (b) the resolved (project, org,
// app, client) tuple from ManageContext is what the command sees.
type fakeDelete struct {
	mu      sync.Mutex
	calls   []DeleteRequest
	revoked int
	err     error
}

func (f *fakeDelete) fn(_ context.Context, req *DeleteRequest) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, *req)
	return f.revoked, f.err
}

func newDELETEDeps(d *fakeDelete) ManageDeps {
	return ManageDeps{
		Queries: &fakeManageQueries{
			row: &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			},
		},
		RATVerifier:       &fakeRATVerifier{},
		Rehasher:          (&fakeRehasher{}).fn,
		AntiEnumDummyHash: "$argon2id$dummy",
		Delete:            d.fn,
	}
}

func serveDELETE(deps ManageDeps, clientID string) *httptest.ResponseRecorder {
	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, chooseDELETEHandler(deps))).Methods(http.MethodDelete)
	req := httptest.NewRequest(http.MethodDelete, "/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer zdrat_xxx")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestDELETE_Stub_WhenDeleteNotWired pins chooseDELETEHandler — when
// ManageDeps.Delete is nil the route serves the 501 stub (uniform
// envelope rather than a wiring panic / 500).
func TestDELETE_Stub_WhenDeleteNotWired(t *testing.T) {
	deps := ManageDeps{
		Queries: &fakeManageQueries{
			row: &ManageRATRow{
				AppID: "app-1", ProjectID: "proj-1", ResourceOwner: "org-1",
				TokenHash: "$argon2id$stored",
			},
		},
		RATVerifier:       &fakeRATVerifier{},
		Rehasher:          (&fakeRehasher{}).fn,
		AntiEnumDummyHash: "$argon2id$dummy",
		// Delete intentionally nil.
	}
	rec := serveDELETE(deps, "client-1")
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

// TestDELETE_Success_204 covers cavekit-manage-handler.md R6 AC1 —
// successful DELETE returns 204 No Content with an empty body.
func TestDELETE_Success_204(t *testing.T) {
	d := &fakeDelete{revoked: 3}
	deps := newDELETEDeps(d)

	rec := serveDELETE(deps, "client-1")

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String(), "R6 AC1: 204 body must be empty")
	require.Len(t, d.calls, 1)
	assert.Equal(t, "proj-1", d.calls[0].ProjectID, "project routes from ManageContext")
	assert.Equal(t, "org-1", d.calls[0].OrgID, "org routes from ManageContext (resource_owner)")
	assert.Equal(t, "app-1", d.calls[0].AppID, "app routes from ManageContext")
	assert.Equal(t, "client-1", d.calls[0].ClientID, "client_id routes from ManageContext")
}

// TestDELETE_DispatchError_Mapped500 — when the command-layer Delete
// returns a non-ClampError, the dispatcher maps it to 500 server_error
// without echoing the wrapped error string (R8 fingerprint guard).
func TestDELETE_DispatchError_Mapped500(t *testing.T) {
	d := &fakeDelete{err: errors.New("eventstore push failed: deep internal")}
	deps := newDELETEDeps(d)

	rec := serveDELETE(deps, "client-1")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"server_error"`)
	assert.NotContains(t, rec.Body.String(), "deep internal")
}

// TestDELETE_DispatchClampErrorPropagates — when the command returns a
// *ClampError (e.g. NotFound mapped to invalid_token), the dispatcher
// honours the embedded HTTP status + envelope code.
func TestDELETE_DispatchClampErrorPropagates(t *testing.T) {
	d := &fakeDelete{err: &ClampError{
		Status:      http.StatusUnauthorized,
		Code:        ErrCodeInvalidToken,
		Description: "client not found",
	}}
	deps := newDELETEDeps(d)

	rec := serveDELETE(deps, "unknown")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"),
		"R8: 401 invalid_token MUST carry WWW-Authenticate")
}

// TestDELETE_NoBearer_401_DoesNotCallDelete — bearer-presence gate
// short-circuits before the Delete closure runs (no revocation /
// removal triggered by an unauthenticated DELETE).
func TestDELETE_NoBearer_401_DoesNotCallDelete(t *testing.T) {
	d := &fakeDelete{}
	deps := newDELETEDeps(d)

	router := mux.NewRouter()
	router.HandleFunc("/{client_id}", manageVerifyDispatch(deps, chooseDELETEHandler(deps))).Methods(http.MethodDelete)
	req := httptest.NewRequest(http.MethodDelete, "/client-1", nil)
	// no Authorization header
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, d.calls, "missing Bearer MUST short-circuit before Delete is called")
}

// TestDELETE_NoManageContext_500 — defensive contract: handler invoked
// without manageVerifyDispatch returns 500 not a panic.
func TestDELETE_NoManageContext_500(t *testing.T) {
	d := &fakeDelete{}
	deps := newDELETEDeps(d)
	h := deleteClientHandler(deps)
	req := httptest.NewRequest(http.MethodDelete, "/client-1", nil)
	rec := httptest.NewRecorder()
	h(rec, req.WithContext(context.Background()))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"error":"server_error"`)
	assert.Empty(t, d.calls)
}
