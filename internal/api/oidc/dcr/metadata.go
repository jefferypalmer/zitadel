package dcr

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
