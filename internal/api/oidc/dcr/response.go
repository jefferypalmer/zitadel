package dcr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// RegistrationResponse is the wire-format struct emitted by a successful
// POST /oidc/v1/register per RFC 7591 §3.2.1. Fields are echoed back
// from the clamped metadata that survived ValidateAndClampMetadata
// (T-034) so the client sees exactly what the server stored — never the
// pre-clamp version.
//
// Pointer types (`*int64`) are used where RFC 7591 distinguishes
// "field absent" from "field present with zero value". `client_secret`
// uses `omitempty` so auth_method=none clients receive a body without
// the key at all (R7 AC: "client_secret WHEN AND ONLY WHEN
// auth_method ∈ {basic, post}").
//
// `client_secret_expires_at` deliberately does NOT use omitempty: RFC
// 7591 §3.2.1 specifies that the value `0` means "no expiry" — a
// MUST-emit sentinel. Same convention extends to RAT lifetime (zero
// when `RATLifetime=0`); that one rides on a separate optional field.
type RegistrationResponse struct {
	// Server-generated identity.
	ClientID              string `json:"client_id"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`

	// One-time RFC 7592 RAT (returned to the caller exactly once).
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`

	// Echoed clamped metadata. Each field is the post-clamp form per
	// T-034 / T-039 — clients that sent disallowed values see them
	// dropped here.
	ClientName                  string                 `json:"client_name,omitempty"`
	RedirectURIs                []string               `json:"redirect_uris,omitempty"`
	GrantTypes                  []string               `json:"grant_types,omitempty"`
	ResponseTypes               []string               `json:"response_types,omitempty"`
	TokenEndpointAuthMethod     string                 `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType             string                 `json:"application_type,omitempty"`
	PostLogoutRedirectURIs      []string               `json:"post_logout_redirect_uris,omitempty"`
	BackChannelLogoutURI        string                 `json:"backchannel_logout_uri,omitempty"`
	SubjectType                 string                 `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg    string                 `json:"id_token_signed_response_alg,omitempty"`
	JwksURI                     string                 `json:"jwks_uri,omitempty"`
	Scope                       string                 `json:"scope,omitempty"`
	Contacts                    []string               `json:"contacts,omitempty"`
	LogoURI                     string                 `json:"logo_uri,omitempty"`
	ClientURI                   string                 `json:"client_uri,omitempty"`
	PolicyURI                   string                 `json:"policy_uri,omitempty"`
	TosURI                      string                 `json:"tos_uri,omitempty"`
	SoftwareID                  string                 `json:"software_id,omitempty"`
	SoftwareVersion             string                 `json:"software_version,omitempty"`
	DefaultMaxAge               *int                   `json:"default_max_age,omitempty"`
	RequireAuthTime             *bool                  `json:"require_auth_time,omitempty"`
	DefaultACRValues            []string               `json:"default_acr_values,omitempty"`
	InitiateLoginURI            string                 `json:"initiate_login_uri,omitempty"`
}

// RegistrationOutput is the input the response writer needs from the
// upstream pipeline. Decouples the writer from `command.RegisterClientResult`
// so the dcr package doesn't depend on internal/command.
type RegistrationOutput struct {
	// Identity + secrets — sourced from command.RegisterClientResult
	// (T-040). RATPlaintext / RATExpiresAt are the one-time values
	// returned to the client.
	ClientID              string
	ClientSecret          string
	ClientSecretExpiresIn time.Duration
	RATPlaintext          string
	RATExpiresAt          time.Time
	ClientIDIssuedAt      time.Time

	// Clamped metadata — sourced from `*RFC7591Metadata` AFTER
	// ValidateAndClampMetadata (T-034). The handler dispatcher (T-033)
	// owns this fan-out; the response writer just echoes.
	Clamped *RFC7591Metadata
}

// WriteRegistrationResponse emits the RFC 7591 §3.2.1 success body to
// `w` for the freshly-registered client. Implements
// cavekit-register-handler.md R7.
//
// Header contract per R7:
//   - Status 201 Created.
//   - `Content-Type: application/json;charset=UTF-8`.
//   - `Cache-Control: no-store` and `Pragma: no-cache` (RFC 7591 §3.2.1
//     defence — stops a caching proxy from replaying the one-time RAT
//     to a different client).
//
// Body shape per R7:
//   - `client_id` — server-generated.
//   - `client_id_issued_at` — unix seconds.
//   - `client_secret` — present iff non-empty (auth_method ∈
//     {basic, post}; T-040 omits it for none/private_key_jwt).
//   - `client_secret_expires_at` — unix seconds; `0` sentinel when
//     `ClientSecretExpiresIn=0` (RFC 7591 §3.2.1 "no expiry").
//   - `registration_access_token` — plaintext, returned exactly once.
//   - `registration_client_uri` — `<issuer>/oidc/v1/register/<client_id>`
//     via op.IssuerFromContext (matches the discovery
//     `registration_endpoint` per R3 of cavekit-discovery-and-as-metadata.md).
//   - All clamped metadata echoed back (every field the server stored).
//
// Returns the encode error, if any. The handler dispatcher should NOT
// retry on a write failure — the events have already been pushed and
// the RAT plaintext is gone the moment this function returns even if
// the wire write was partial.
func WriteRegistrationResponse(ctx context.Context, w http.ResponseWriter, out *RegistrationOutput) error {
	if out == nil || out.Clamped == nil {
		return fmt.Errorf("dcr: WriteRegistrationResponse requires non-nil output and clamped metadata")
	}

	body := buildRegistrationResponse(ctx, out)

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(body)
}

// buildRegistrationResponse is the pure-function form used by both
// WriteRegistrationResponse and the unit tests so the body shape can
// be asserted without a full http.ResponseWriter round-trip.
func buildRegistrationResponse(ctx context.Context, out *RegistrationOutput) *RegistrationResponse {
	resp := &RegistrationResponse{
		ClientID:              out.ClientID,
		ClientIDIssuedAt:      out.ClientIDIssuedAt.Unix(),
		ClientSecret:          out.ClientSecret,
		ClientSecretExpiresAt: clientSecretExpiresAtFor(out),

		RegistrationAccessToken: out.RATPlaintext,
		RegistrationClientURI:   buildRegistrationClientURI(ctx, out.ClientID),

		ClientName:               out.Clamped.ClientName,
		RedirectURIs:             out.Clamped.RedirectURIs,
		GrantTypes:               out.Clamped.GrantTypes,
		ResponseTypes:            out.Clamped.ResponseTypes,
		TokenEndpointAuthMethod:  out.Clamped.TokenEndpointAuthMethod,
		ApplicationType:          out.Clamped.ApplicationType,
		PostLogoutRedirectURIs:   out.Clamped.PostLogoutRedirectURIs,
		BackChannelLogoutURI:     out.Clamped.BackChannelLogoutURI,
		SubjectType:              out.Clamped.SubjectType,
		IDTokenSignedResponseAlg: out.Clamped.IDTokenSignedResponseAlg,
		JwksURI:                  out.Clamped.JwksURI,
		Scope:                    out.Clamped.Scope,
		Contacts:                 out.Clamped.Contacts,
		LogoURI:                  out.Clamped.LogoURI,
		ClientURI:                out.Clamped.ClientURI,
		PolicyURI:                out.Clamped.PolicyURI,
		TosURI:                   out.Clamped.TosURI,
		SoftwareID:               out.Clamped.SoftwareID,
		SoftwareVersion:          out.Clamped.SoftwareVersion,
		DefaultMaxAge:            out.Clamped.DefaultMaxAge,
		RequireAuthTime:          out.Clamped.RequireAuthTime,
		DefaultACRValues:         out.Clamped.DefaultACRValues,
		InitiateLoginURI:         out.Clamped.InitiateLoginURI,
	}
	return resp
}

// clientSecretExpiresAtFor returns the RFC 7591 §3.2.1 sentinel when no
// expiry is configured. Returns 0 when no client_secret was issued (so
// the handler doesn't lie about an absent secret expiring at "0", which
// would still semantically read as "no expiry" — RFC 7591 is silent on
// the field's value when the secret is absent; we keep the 0 sentinel
// so the field stays present and non-misleading).
func clientSecretExpiresAtFor(out *RegistrationOutput) int64 {
	if out.ClientSecretExpiresIn == 0 {
		return 0
	}
	return out.ClientIDIssuedAt.Add(out.ClientSecretExpiresIn).Unix()
}

// buildRegistrationClientURI returns
// `<issuer>/oidc/v1/register/<client_id>` per R7 AC. When
// op.IssuerFromContext returns empty (e.g. the request didn't ride
// through op.middleware), returns just `<HandlerPrefix>/<client_id>` so
// the body still parses; the handler dispatcher MUST run inside the OIDC
// op.IssuerFromContext middleware so this fallback should not fire in
// production.
func buildRegistrationClientURI(ctx context.Context, clientID string) string {
	issuer := op.IssuerFromContext(ctx)
	if issuer == "" {
		return HandlerPrefix + "/" + clientID
	}
	return trimTrailingSlash(issuer) + HandlerPrefix + "/" + clientID
}

func trimTrailingSlash(s string) string {
	if len(s) == 0 || s[len(s)-1] != '/' {
		return s
	}
	return s[:len(s)-1]
}
