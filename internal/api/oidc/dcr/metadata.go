package dcr

import (
	"encoding/json"

	"github.com/zitadel/zitadel/internal/domain"
)

// RFC7591Metadata is the RFC 7591 client-metadata request body. Field
// names + JSON tags match RFC 7591 §2 + OIDC Registration 1.0 §2
// verbatim. Unknown JSON fields land in `Extra` for T-033 to ignore /
// drop and for T-039 to route into the `dcr_meta` JSONB column.
//
// Pointer fields distinguish "absent" from "explicitly empty/zero":
// T-033's default-population pass needs to know whether a caller sent
// `"grant_types": []` (explicit empty → 400) versus omitting the key
// (apply RFC 7591 §2 default).
type RFC7591Metadata struct {
	// RFC 7591 §2 / OIDC Reg 1.0 §2 — clamped fields.
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	BackChannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`

	// OIDC Registration 1.0 §2 — clamped/rejected fields.
	SubjectType                  string `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg     string `json:"id_token_signed_response_alg,omitempty"`
	RequestObjectSigningAlg      string `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   string `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   string `json:"request_object_encryption_enc,omitempty"`

	// JWKS / private_key_jwt support.
	JwksURI string `json:"jwks_uri,omitempty"`

	// Inline JWK Set per RFC 7591 §2 (`jwks`). Mutually exclusive with
	// `jwks_uri` (cavekit-inline-jwks.md R1). Stored as RawMessage so
	// jwks_inline.Validate (T-007) can apply per-JWK rules without
	// re-decoding generic JSON in `validate.go`. nil = absent (Phase 1
	// behaviour); non-nil = caller sent a `jwks` key (validators must
	// run, including the empty-keys-array refusal).
	Jwks json.RawMessage `json:"jwks,omitempty"`

	// Software statement (rejected in Phase 1 when feature off).
	SoftwareStatement string `json:"software_statement,omitempty"`

	// RFC 7591 §2 — pass-through fields routed into dcr_meta JSONB.
	// Listed here so the JSON decoder doesn't need an Extra-map; T-039
	// reads these to populate dcr_meta.
	Contacts          []string `json:"contacts,omitempty"`
	LogoURI           string   `json:"logo_uri,omitempty"`
	ClientURI         string   `json:"client_uri,omitempty"`
	PolicyURI         string   `json:"policy_uri,omitempty"`
	TosURI            string   `json:"tos_uri,omitempty"`
	SoftwareID        string   `json:"software_id,omitempty"`
	SoftwareVersion   string   `json:"software_version,omitempty"`
	DefaultMaxAge     *int     `json:"default_max_age,omitempty"`
	RequireAuthTime   *bool    `json:"require_auth_time,omitempty"`
	DefaultACRValues  []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI  string   `json:"initiate_login_uri,omitempty"`
	Scope             string   `json:"scope,omitempty"`
}

// ToOIDCApp bridges a clamped [RFC7591Metadata] to a [domain.OIDCApp]
// via the domain-level mapping function (cavekit-register-handler.md
// R6 / T-039). Caller MUST run [ValidateAndClampMetadata] first; this
// function performs no validation.
func (m *RFC7591Metadata) ToOIDCApp() *domain.OIDCApp {
	if m == nil {
		return nil
	}
	return domain.OIDCAppFromRFC7591Metadata(
		m.ClientName,
		m.RedirectURIs,
		m.GrantTypes,
		m.ResponseTypes,
		m.TokenEndpointAuthMethod,
		m.ApplicationType,
		m.PostLogoutRedirectURIs,
		m.BackChannelLogoutURI,
	)
}

// BuildDCRMeta extracts the RFC 7591 §2 fields that are stored in the
// `dcr_meta` JSONB column without acting on them
// (cavekit-register-handler.md R6 AC: "Other RFC 7591 fields are
// stored in the dcr_meta JSONB column"). The returned map contains
// only fields the caller actually populated — empty / zero / nil
// fields are omitted so the persisted JSON stays small.
//
// Pass-through fields (per kit R6):
//   contacts, logo_uri, client_uri, policy_uri, tos_uri,
//   software_id, software_version, default_max_age, require_auth_time,
//   default_acr_values, initiate_login_uri.
//
// `scope` is also passed through because OIDC Reg 1.0 §2 lists it as
// a registration-time hint and Phase 1 doesn't act on it.
func (m *RFC7591Metadata) BuildDCRMeta() map[string]any {
	if m == nil {
		return nil
	}
	out := map[string]any{}
	if len(m.Contacts) > 0 {
		out["contacts"] = append([]string(nil), m.Contacts...)
	}
	if m.LogoURI != "" {
		out["logo_uri"] = m.LogoURI
	}
	if m.ClientURI != "" {
		out["client_uri"] = m.ClientURI
	}
	if m.PolicyURI != "" {
		out["policy_uri"] = m.PolicyURI
	}
	if m.TosURI != "" {
		out["tos_uri"] = m.TosURI
	}
	if m.SoftwareID != "" {
		out["software_id"] = m.SoftwareID
	}
	if m.SoftwareVersion != "" {
		out["software_version"] = m.SoftwareVersion
	}
	if m.DefaultMaxAge != nil {
		out["default_max_age"] = *m.DefaultMaxAge
	}
	if m.RequireAuthTime != nil {
		out["require_auth_time"] = *m.RequireAuthTime
	}
	if len(m.DefaultACRValues) > 0 {
		out["default_acr_values"] = append([]string(nil), m.DefaultACRValues...)
	}
	if m.InitiateLoginURI != "" {
		out["initiate_login_uri"] = m.InitiateLoginURI
	}
	if m.Scope != "" {
		out["scope"] = m.Scope
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
