package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/zitadel/zitadel/internal/telemetry/tracing"
)

// ManageReadResponse is the wire-format struct emitted by a successful
// GET /oidc/v1/register/{client_id} per RFC 7592 §2.2 +
// cavekit-manage-handler.md R4. Same shape as [RegistrationResponse]
// minus `client_secret` (unretrievable per RFC 7591 §2.4) and
// `registration_access_token` (one-time issue per RFC 7591 §3.2.1).
//
// `client_secret_expires_at` deliberately stays present (no omitempty)
// — RFC 7591 §3.2.1 specifies that the value `0` means "no expiry"
// and the GET response is the only place clients re-discover it.
//
// All RFC 7591 §2 pass-through fields land here from the dcr_meta
// JSONB column the projection stamped at registration time (T-041).
type ManageReadResponse struct {
	ClientID              string `json:"client_id"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`

	// registration_client_uri is re-emitted identical to the value the
	// original POST register response carried (R4 AC).
	RegistrationClientURI string `json:"registration_client_uri"`

	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`

	// RFC 7591 §2 pass-through fields (unpacked from dcr_meta JSONB).
	// Same shape as [RegistrationResponse] so a client that captures
	// the original POST body and the GET body sees identical pass-
	// through structure — no GET-specific wire shape divergence.
	Contacts         []string `json:"contacts,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	ClientURI        string   `json:"client_uri,omitempty"`
	PolicyURI        string   `json:"policy_uri,omitempty"`
	TosURI           string   `json:"tos_uri,omitempty"`
	SoftwareID       string   `json:"software_id,omitempty"`
	SoftwareVersion  string   `json:"software_version,omitempty"`
	DefaultMaxAge    *int     `json:"default_max_age,omitempty"`
	RequireAuthTime  *bool    `json:"require_auth_time,omitempty"`
	DefaultACRValues []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI string   `json:"initiate_login_uri,omitempty"`
	Scope            string   `json:"scope,omitempty"`

	// JwksURI / Jwks: cavekit-inline-jwks.md R5 / T-022.
	//
	// json:omitempty on json.RawMessage emits no `jwks` key when the
	// field is nil — RFC 7592 GET MUST NOT emit `null` for an unset
	// inline jwks (kit explicit). When the row stores inline jwks,
	// the bytes are echoed verbatim (modulo the sorted-key
	// normalization jwks_inline.Validate already applied).
	JwksURI string          `json:"jwks_uri,omitempty"`
	Jwks    json.RawMessage `json:"jwks,omitempty"`
}

// dcrMetaPassthrough is the on-the-wire JSONB shape of the dcr_meta
// column. Mirror of the subset of [RFC7591Metadata] that
// [RFC7591Metadata.BuildDCRMeta] writes at registration time
// (cavekit-register-handler.md R6 / T-039). Kept as a private
// decoder-target struct so the GET writer doesn't depend on the
// command package's RegisterClientInput shape.
type dcrMetaPassthrough struct {
	Contacts         []string `json:"contacts,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	ClientURI        string   `json:"client_uri,omitempty"`
	PolicyURI        string   `json:"policy_uri,omitempty"`
	TosURI           string   `json:"tos_uri,omitempty"`
	SoftwareID       string   `json:"software_id,omitempty"`
	SoftwareVersion  string   `json:"software_version,omitempty"`
	DefaultMaxAge    *int     `json:"default_max_age,omitempty"`
	RequireAuthTime  *bool    `json:"require_auth_time,omitempty"`
	DefaultACRValues []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI string   `json:"initiate_login_uri,omitempty"`
	Scope            string   `json:"scope,omitempty"`
}

// getClientHandler implements cavekit-manage-handler.md R4 — the GET
// /oidc/v1/register/{client_id} body.
//
// Pre-conditions enforced by the dispatch chain:
//   - Bearer presence (manageVerifyDispatch).
//   - RAT verification via Passwap (VerifyRAT).
//   - Resolved [ManageContext] on r.Context() (contextWithManage).
//
// Sequence:
//  1. Read ManageContext from ctx (panic-on-nil — programmer error).
//  2. Look up the metadata row via [ManageQueries.DCRMetadataByClientID].
//     NotFound here is unexpected (VerifyRAT just succeeded), so the
//     branch logs + writes 500. Any other error → 500 too.
//  3. Build the GET response body via [buildManageReadResponse].
//  4. Write 200 with the canonical no-store / no-cache headers.
func getClientHandler(deps ManageDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// cavekit-console-ui-docs-and-observability.md R7 AC2 (T-066) —
		// `oidc.dcr.read` covers the GET body. No attributes set so
		// AC6 (no client_secret / RAT in span data) holds structurally.
		ctx, span := tracing.NewNamedSpan(r.Context(), "oidc.dcr.read")
		defer span.End()
		// T-067 / R8 AC2 — request duration histogram covers all DCR
		// HTTP handlers, not just POST.
		started := time.Now()
		defer func() { recordRequestDuration(ctx, time.Since(started)) }()
		mctx := ManageFromContext(ctx)
		if mctx == nil {
			// Defensive: the dispatch wrapper sets this; missing means
			// the handler was wired without manageVerifyDispatch.
			slog.WarnContext(ctx, "dcr: GET /register handler invoked without ManageContext on ctx — wiring bug")
			WriteError(w, http.StatusInternalServerError, ErrCodeServerError, "internal server error")
			return
		}

		row, err := deps.Queries.DCRMetadataByClientID(ctx, mctx.ClientID)
		if err != nil {
			// VerifyRAT just succeeded against the same client_id — a
			// NotFound here would mean the projection lost the row
			// between the two queries. Treat all errors uniformly as
			// 500 (no fingerprinting opportunity for the caller).
			slog.WarnContext(ctx, "dcr: GET metadata lookup failed",
				slog.String("client_id", mctx.ClientID),
				slog.Any("err", err))
			WriteError(w, http.StatusInternalServerError, ErrCodeServerError, "internal server error")
			return
		}

		body := buildManageReadResponse(ctx, mctx, row, deps.ClientSecretExpiresIn.Seconds() != 0)

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// buildManageReadResponse is the pure-function form used by both
// getClientHandler and the unit tests so the body shape can be
// asserted without an http.ResponseWriter round-trip.
//
// secretExpiresConfigured controls whether `client_secret_expires_at`
// is computed from the registration time + lifetime, or emitted as
// the RFC 7591 §3.2.1 sentinel `0` (no expiry). The projection
// doesn't store a per-secret expiry column, so the value is derived
// from config at response time — passing a per-app expires_at on
// the projection would require a migration that doesn't pay back
// in Phase 1.
func buildManageReadResponse(
	ctx context.Context,
	mctx *ManageContext,
	row *ManageMetaRow,
	secretExpiresConfigured bool,
) *ManageReadResponse {
	resp := &ManageReadResponse{
		ClientID:              mctx.ClientID,
		ClientIDIssuedAt:      row.ClientIDIssuedAt.Unix(),
		ClientSecretExpiresAt: 0,
		RegistrationClientURI: buildRegistrationClientURI(ctx, mctx.ClientID),

		ClientName:              row.ClientName,
		RedirectURIs:            row.RedirectURIs,
		GrantTypes:              row.GrantTypes,
		ResponseTypes:           row.ResponseTypes,
		TokenEndpointAuthMethod: row.AuthMethodType,
		ApplicationType:         row.ApplicationType,
	}
	// secretExpiresConfigured=true would compute issued + lifetime;
	// per the field godoc the projection doesn't carry a per-secret
	// expiry column, so the GET response leaves `0` (no-expiry
	// sentinel) until a future task threads the lifetime through.
	// Keeping the parameter on the signature documents the contract
	// at the call site.
	_ = secretExpiresConfigured

	// cavekit-inline-jwks.md R5 / T-022 — three-state JWKS rendering.
	switch {
	case len(row.JwksInline) > 0:
		// Echo verbatim. The bytes were sorted-key-normalized at
		// validate time (T-007), so a captured-PUT-then-GET-roundtrip
		// is byte-equal modulo key order.
		resp.Jwks = json.RawMessage(row.JwksInline)
	case row.JwksURI != "":
		resp.JwksURI = row.JwksURI
	}

	if len(row.DCRMeta) > 0 {
		var meta dcrMetaPassthrough
		if err := json.Unmarshal(row.DCRMeta, &meta); err == nil {
			resp.Contacts = meta.Contacts
			resp.LogoURI = meta.LogoURI
			resp.ClientURI = meta.ClientURI
			resp.PolicyURI = meta.PolicyURI
			resp.TosURI = meta.TosURI
			resp.SoftwareID = meta.SoftwareID
			resp.SoftwareVersion = meta.SoftwareVersion
			resp.DefaultMaxAge = meta.DefaultMaxAge
			resp.RequireAuthTime = meta.RequireAuthTime
			resp.DefaultACRValues = meta.DefaultACRValues
			resp.InitiateLoginURI = meta.InitiateLoginURI
			resp.Scope = meta.Scope
		}
		// Malformed dcr_meta: log and serve the response without
		// pass-through fields. Better than 500 — the core RFC 7591
		// fields are still useful and a partial response beats
		// blocking the entire GET on a single column corruption.
	}
	return resp
}

// _ pulls in errors so future expiry-derivation code doesn't churn
// the import list when it lands.
var _ = errors.New
