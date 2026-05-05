package start

import (
	"net/http"

	"github.com/zitadel/zitadel/internal/api/oidc/dcr"
)

// dcrWriteRecoverError is the panic-handler writer wired into the
// middleware.RecoverHandler chain that wraps the DCR routes.
// cavekit-manage-handler.md R9 (T-025): DCR routes mount independently
// of oidcServer.Handler, so the OIDC RecoverHandler does NOT catch
// panics raised under /oidc/v1/register. Without this writer, an R8
// ManageFromContext panic falls through to FallbackRecoverHandler and
// returns text/plain — instead of the RFC 7591 §3.2.2 JSON envelope
// DCR clients expect.
//
// Mirrors dcr.WriteError's contract: 500 status, application/json,
// Cache-Control: no-store, body shaped {"error","error_description"}.
// The recovered error is logged by middleware.RecoverHandler at Alert
// level before this writer runs; we MUST NOT echo the panic message
// or stack into the response body — internal details stay internal.
func dcrWriteRecoverError(w http.ResponseWriter, _ *http.Request, _ error) {
	dcr.WriteError(w, http.StatusInternalServerError, dcr.ErrCodeServerError, "internal server error")
}
