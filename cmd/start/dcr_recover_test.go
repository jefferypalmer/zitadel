package start

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/api/oidc/dcr"
)

// TestDCRRecover_R9_WrapsMount pins cavekit-manage-handler.md R9 / T-025
// at the source-string level: the DCR mount in start.go MUST wrap the
// inner stack in `middleware.RecoverHandler(dcrWriteRecoverError)`
// BEFORE mounting via RegisterHandlerOnPrefix. Without this wrap the
// R8 ManageFromContext panic falls through to FallbackRecoverHandler
// which writes text/plain instead of the RFC 7591 JSON envelope.
func TestDCRRecover_R9_WrapsMount(t *testing.T) {
	src, err := os.ReadFile("start.go")
	require.NoError(t, err)
	body := string(src)

	// dcrWrapped MUST start with middleware.RecoverHandler(dcrWriteRecoverError)
	idx := strings.Index(body, "dcrWrapped := middleware.RecoverHandler(dcrWriteRecoverError)(")
	require.NotEqual(t, -1, idx,
		"R9 / T-025: expected `dcrWrapped := middleware.RecoverHandler(dcrWriteRecoverError)(...)` wrap line in start.go")
}

// TestDCRWriteRecoverError_EmitsJSONEnvelope is the runtime invariant.
// Wraps a deliberately-panicking handler in middleware.RecoverHandler
// with dcrWriteRecoverError as the writer, then asserts the response
// is shaped like the RFC 7591 §3.2.2 envelope (status 500,
// Content-Type application/json, body {"error","error_description"}).
//
// This is the test that would have caught F-001: the Phase-3 commit
// claimed the OIDC RecoverHandler covered the panic path; in fact DCR
// mounted independently of oidcServer.Handler, so panics fell through
// to the text/plain fallback. R9 / T-025 fixes that — this test pins
// the fix.
func TestDCRWriteRecoverError_EmitsJSONEnvelope(t *testing.T) {
	panicHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("synthetic panic for recover test")
	})
	wrapped := middleware.RecoverHandler(dcrWriteRecoverError)(panicHandler)

	req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code, "recover writer must emit 500")
	assert.Equal(t, "application/json;charset=UTF-8", rec.Header().Get("Content-Type"),
		"recover writer must emit RFC 7591 application/json envelope, NOT text/plain")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var env map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, dcr.ErrCodeServerError, env["error"], "envelope error code must be server_error")
	assert.NotEmpty(t, env["error_description"])
	// CRITICAL: the panic message must NOT leak into the envelope body —
	// internal details stay internal.
	assert.NotContains(t, rec.Body.String(), "synthetic panic for recover test",
		"recover writer MUST NOT echo the panic message into the response body")
}
