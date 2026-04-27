package dcr

import (
	"log/slog"
	"net/http"

	"github.com/zitadel/zitadel/internal/telemetry/tracing"
)

// deleteClientHandler implements cavekit-manage-handler.md R6 (T-056) —
// the DELETE /oidc/v1/register/{client_id} body. Pre-conditions
// enforced by the dispatch chain (manageVerifyDispatch →
// contextWithManage → ManageContext on r.Context()) are identical to
// GET / PUT.
//
// Sequence:
//  1. Read ManageContext from ctx (panic-on-nil → 500 server_error).
//  2. Call ManageDeps.Delete — the command layer revokes outstanding
//     access / refresh tokens (path-(a) per the M4 worker decision /
//     T-007) AND removes the application atomically per-aggregate.
//  3. Write 204 No Content (R6 AC1).
//
// On any *ClampError from Delete the handler maps directly through
// [writeDispatchError]. Non-ClampError → 500 server_error (R8
// fingerprint guard — internal error strings MUST NOT echo to the
// caller).
func deleteClientHandler(deps ManageDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// cavekit-console-ui-docs-and-observability.md R7 AC4 (T-066).
		ctx, span := tracing.NewNamedSpan(r.Context(), "oidc.dcr.delete")
		defer span.End()
		mctx := ManageFromContext(ctx)
		if mctx == nil {
			slog.WarnContext(ctx, "dcr: DELETE /register handler invoked without ManageContext on ctx — wiring bug")
			WriteError(w, http.StatusInternalServerError, ErrCodeServerError, "internal server error")
			return
		}

		revoked, err := deps.Delete(ctx, &DeleteRequest{
			ProjectID: mctx.ProjectID,
			OrgID:     mctx.ResourceOwner,
			AppID:     mctx.AppID,
			ClientID:  mctx.ClientID,
		})
		if err != nil {
			// Use writeAuthError so a *ClampError carrying invalid_token
			// (e.g. a future projection-lag NotFound mapping) gets the
			// WWW-Authenticate header per R8 AC. All other ClampError
			// codes fall through to writeDispatchError unchanged.
			writeAuthError(ctx, w, err)
			return
		}

		// Audit-log the revoked-session count so operators can
		// correlate a DELETE with the volume of revocation events
		// pushed onto the bus. Plaintext IDs / IPs are NOT logged
		// here; the bare count is enough for ops correlation and
		// keeps PII out of the log stream.
		slog.InfoContext(ctx, "dcr: client deleted",
			slog.String("client_id", mctx.ClientID),
			slog.Int("revoked_sessions", revoked))

		w.WriteHeader(http.StatusNoContent)
	}
}
