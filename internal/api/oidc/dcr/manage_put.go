package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// ManageUpdateResponse is the wire-format struct emitted by a successful
// PUT /oidc/v1/register/{client_id} per RFC 7592 §2.2 +
// cavekit-manage-handler.md R5 (T-054 — re-clamp + auth-method
// transitions). Same field set as [ManageReadResponse] minus the
// re-emitted RAT (T-055 layers RAT rotation on top of this body).
//
// `client_secret` is emitted ONLY when this PUT minted a fresh secret
// via the `none → client_secret_*` transition (R5 AC3). For all other
// transitions the field is omitted via json:omitempty so an idempotent
// PUT does not accidentally re-emit a stale secret to the caller.
type ManageUpdateResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
}

// putClientHandler implements cavekit-manage-handler.md R5 (T-054) —
// the PUT /oidc/v1/register/{client_id} body. Pre-conditions enforced
// by the dispatch chain (manageVerifyDispatch → contextWithManage →
// ManageContext on r.Context()) are identical to the GET handler's.
//
// Sequence:
//  1. Decode the request body via [Decode] — applies R2 defaults +
//     handles 415/413/400.
//  2. Re-clamp via [ValidateAndClampMetadata] — R4 rules re-run per
//     R5 AC1. The clamp catches `client_secret_jwt` (AC6) and
//     missing-jwks_uri-on-private_key_jwt (AC5) before the command
//     ever sees them.
//  3. Dispatch to [ManageDeps.Update] — the auth-method transition
//     matrix (AC3 + AC4) lives in the command (atomic event push).
//  4. Write 200 with the response body. RAT rotation (AC7-9) is T-055
//     and does NOT touch this handler — when T-055 lands it will
//     compose its rotated RAT into [ManageUpdateResponse].
//
// On any *ClampError from Decode / Validate / Update the handler maps
// directly through [writeDispatchError] so the RFC 7591 envelope code
// + HTTP status are uniform across POST + PUT paths.
func putClientHandler(deps ManageDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		mctx := ManageFromContext(ctx)
		if mctx == nil {
			// Defensive: dispatch wrapper sets this; missing means the
			// handler was wired without manageVerifyDispatch. Same shape
			// the GET handler uses for the equivalent invariant.
			slog.WarnContext(ctx, "dcr: PUT /register handler invoked without ManageContext on ctx — wiring bug")
			WriteError(w, http.StatusInternalServerError, ErrCodeServerError, "internal server error")
			return
		}

		decoded, err := Decode(r, DecodeOptions{MaxBodyBytes: deps.MaxBodyBytes})
		if err != nil {
			writeDispatchError(ctx, w, err)
			return
		}

		clamped, err := ValidateAndClampMetadata(deps.Config, decoded, deps.SupportedSigAlgs, deps.SoftwareStatementEnabled)
		if err != nil {
			writeDispatchError(ctx, w, err)
			return
		}

		req := &UpdateRequest{
			ProjectID: mctx.ProjectID,
			OrgID:     mctx.ResourceOwner,
			AppID:     mctx.AppID,
			Clamped:   clamped,
		}
		result, err := deps.Update(ctx, req)
		if err != nil {
			writeDispatchError(ctx, w, err)
			return
		}

		body := buildManageUpdateResponse(ctx, mctx, clamped, result)

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// buildManageUpdateResponse is the pure function used by the handler
// and the unit tests so the body shape can be asserted without an
// http.ResponseWriter round-trip. Echoes the clamped metadata that
// was just persisted plus (only on the `none → client_secret_*`
// transition) the freshly-minted plaintext secret.
//
// `client_secret_expires_at` stays present (no omitempty) — RFC 7591
// §3.2.1 specifies that the value `0` means "no expiry". The current
// projection does not store a per-secret expires_at column so this
// always emits 0; T-055 may revisit when it threads the lifetime
// through.
func buildManageUpdateResponse(
	ctx context.Context,
	mctx *ManageContext,
	clamped *RFC7591Metadata,
	result *UpdateResult,
) *ManageUpdateResponse {
	resp := &ManageUpdateResponse{
		ClientID:                mctx.ClientID,
		ClientSecret:            result.ClientSecret,
		ClientSecretExpiresAt:   0,
		RegistrationClientURI:   buildRegistrationClientURI(ctx, mctx.ClientID),
		ClientName:              clamped.ClientName,
		RedirectURIs:            clamped.RedirectURIs,
		GrantTypes:              clamped.GrantTypes,
		ResponseTypes:           clamped.ResponseTypes,
		TokenEndpointAuthMethod: clamped.TokenEndpointAuthMethod,
		ApplicationType:         clamped.ApplicationType,
	}
	return resp
}

// _ pulls in errors so future failure-mapping code lands without
// churn (the dispatcher is the only path that maps non-ClampError
// today; that may move into this file once Update stops returning
// raw eventstore errors).
var _ = errors.New
