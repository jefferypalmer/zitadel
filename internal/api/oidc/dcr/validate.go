package dcr

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zitadel/zitadel/internal/api/oidc/dcr/jwks_inline"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// validate.go is the single source of truth for DCR client-metadata
// clamp + validation logic. Consumed by both POST /register
// (cavekit-register-handler.md R4 — T-034) and PUT
// /register/{client_id} (cavekit-manage-handler.md R5 — T-054). The
// two surfaces enforce identical rules by sharing this function.
//
// RFC 7591 §2 default population (T-033 / R2) lives elsewhere — this
// file assumes the caller has already applied defaults. The clamp
// functions here are the second pass: they reject anything outside
// the configured allow-lists or the OIDC v1 compliance envelope.

// ClampError is the structured error type returned by
// [ValidateAndClampMetadata]. The HTTP error body uses
// `Error` as the RFC 7591 error code (always one of the four §3.2.2
// codes) and `Description` as the human-readable text. The wrapped
// error carries the zerror with the `DCR-<5 alpha>` ID for log
// correlation.
type ClampError struct {
	// Status is the HTTP status code the dispatcher should use when
	// emitting WriteError for this error. Zero is treated as 400 by
	// the conventional 4xx mapping (Code is the RFC 7591 envelope
	// code; the spec defines all four code constants as 400-only). The
	// decoder (T-033 / R2) sets non-400 values for the 413 / 415
	// branches.
	Status      int
	Code        string
	Description string
	Wrapped     error
}

// HTTPStatus returns Status when set, otherwise 400 (the RFC 7591
// §3.2.2 default for envelope codes). Lets dispatchers use a uniform
// `WriteError(w, e.HTTPStatus(), e.Code, e.Description)` line.
func (e *ClampError) HTTPStatus() int {
	if e.Status == 0 {
		return 400
	}
	return e.Status
}

func (e *ClampError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("dcr clamp: %s: %s (%v)", e.Code, e.Description, e.Wrapped)
	}
	return fmt.Sprintf("dcr clamp: %s: %s", e.Code, e.Description)
}

func (e *ClampError) Unwrap() error { return e.Wrapped }

func newClampError(code, fieldName, reason, dcrID string) *ClampError {
	desc := fieldName + ": " + reason
	return &ClampError{
		Code:        code,
		Description: desc,
		Wrapped:     zerrors.ThrowInvalidArgument(nil, dcrID, "Errors.DCR.InvalidClientMetadata"),
	}
}

// ValidateAndClampMetadata enforces cavekit-register-handler.md R4
// (T-034) on a defaulted [RFC7591Metadata]. Returns a clamped *copy*
// (the input is not mutated) plus a *ClampError on the first failure.
//
// `supportedIDTokenSigAlgs` is the server's id_token_signing_alg_values_supported
// list (sourced from `supportedSigningAlgs()` in op.go) — needed to
// validate the per-client `id_token_signed_response_alg` against the
// server's actual capabilities (R4 AC).
//
// `softwareStatementEnabled` mirrors `DCR.SoftwareStatement.Enabled`
// from `cavekit-config.md` R1; when false, any non-empty
// `software_statement` is rejected with the RFC 7591 code
// `unapproved_software_statement` per R4.
func ValidateAndClampMetadata(
	cfg DCRConfigSubset,
	in *RFC7591Metadata,
	supportedIDTokenSigAlgs []string,
	softwareStatementEnabled bool,
) (*RFC7591Metadata, error) {
	if in == nil {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "request", "empty body", "DCR-Vt001")
	}
	out := *in // shallow copy; intersected slices are reassigned below.

	// software_statement — present + feature off → unapproved.
	// Done first so the JTI-extraction audit hook (T-040) can fire on
	// this code path before any other rejection.
	if strings.TrimSpace(out.SoftwareStatement) != "" && !softwareStatementEnabled {
		return nil, &ClampError{
			Code:        ErrCodeUnapprovedSoftwareStatement,
			Description: "software_statement: feature disabled — see DCR.SoftwareStatement.Enabled",
			Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-Vt002", "Errors.DCR.UnapprovedSoftwareStatement"),
		}
	}

	// cavekit-inline-jwks.md R1: `jwks` and `jwks_uri` are mutually
	// exclusive. Both, neither (with private_key_jwt), or just one are
	// permitted client metadata; this check is for the both-set case.
	// R1 also forbids non-object jwks / non-array keys / empty keys
	// arrays — those checks live in jwks_inline.Validate (T-007).
	hasInlineJwks := len(out.Jwks) > 0
	hasJwksURI := strings.TrimSpace(out.JwksURI) != ""
	if hasInlineJwks && hasJwksURI {
		return nil, &ClampError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: "jwks and jwks_uri are mutually exclusive — provide one or the other, not both",
			Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-VtJk1", jwks_inline.KeyMutuallyExclusive),
		}
	}
	if hasInlineJwks {
		canonical, vErr := jwks_inline.Validate(out.Jwks)
		if vErr != nil {
			return nil, &ClampError{
				Code:        vErr.Code,
				Description: vErr.Description,
				Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-VtJk2", vErr.I18nKey),
			}
		}
		// Replace the body's `jwks` with the canonicalised bytes so
		// downstream storage / R5 echo gets the byte-stable form.
		out.Jwks = canonical
	}

	// grant_types — empty after defaulting is a 400.
	if len(out.GrantTypes) == 0 {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "grant_types", "must not be empty", "DCR-Vt003")
	}
	clampedGrants := intersectStringSlice(out.GrantTypes, cfg.AllowedGrantTypes())
	if len(clampedGrants) == 0 {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "grant_types",
			"none of the requested values are allowed by DCR.AllowedGrantTypes", "DCR-Vt004")
	}
	out.GrantTypes = clampedGrants

	// response_types — empty after defaulting is a 400.
	if len(out.ResponseTypes) == 0 {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "response_types", "must not be empty", "DCR-Vt005")
	}
	// cavekit-register-handler.md R4 amendment 2026-04-27 / F-103: RFC
	// 6749 §3.1.1 defines response_type values as space-separated SETS
	// of tokens; `"token id_token"` ≡ `"id_token token"`. Canonicalize
	// both sides before set-membership comparison, then echo the
	// allow-list spelling (which mirrors zitadel/oidc/v3's canonical
	// strings) on output so the rest of the OIDC stack — which switches
	// on those exact literals at
	// internal/api/oidc/auth_request_converter.go::ResponseTypeToBusiness —
	// sees consistent values.
	clampedRT := intersectResponseTypes(out.ResponseTypes, cfg.AllowedResponseTypes())
	if len(clampedRT) == 0 {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "response_types",
			"none of the requested values are allowed by DCR.AllowedResponseTypes", "DCR-Vt006")
	}
	out.ResponseTypes = clampedRT

	// token_endpoint_auth_method — special-case `client_secret_jwt`
	// rejection so the error_description names the policy reason rather
	// than just "not in allow-list".
	if out.TokenEndpointAuthMethod == "client_secret_jwt" {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "token_endpoint_auth_method",
			"client_secret_jwt is not supported", "DCR-Vt007")
	}
	if !slices.Contains(cfg.AllowedAuthMethods(), out.TokenEndpointAuthMethod) {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "token_endpoint_auth_method",
			"not in DCR.AllowedAuthMethods", "DCR-Vt008")
	}
	// private_key_jwt REQUIRES jwks_uri per cavekit-register-handler.md
	// R5 AC3 (and OIDC Reg 1.0 §5.2.1: when token_endpoint_auth_method
	// is private_key_jwt, the client MUST register a key — Phase 1 only
	// supports the by-reference form via jwks_uri; inline `jwks` is
	// out-of-scope per kit). Missing jwks_uri here would otherwise leave
	// the client unauthenticatable at /token.
	if out.TokenEndpointAuthMethod == "private_key_jwt" &&
		strings.TrimSpace(out.JwksURI) == "" && len(out.Jwks) == 0 {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "jwks_uri",
			"jwks_uri or jwks is required when token_endpoint_auth_method=private_key_jwt", "DCR-Vt0R5")
	}

	// application_type
	if !slices.Contains(cfg.AllowedApplicationTypes(), out.ApplicationType) {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "application_type",
			"not in DCR.AllowedApplicationTypes", "DCR-Vt009")
	}

	// subject_type — accept "public" or absent; reject "pairwise".
	if out.SubjectType != "" && out.SubjectType != "public" {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "subject_type",
			"only 'public' is supported", "DCR-Vt010")
	}

	// id_token_signed_response_alg — when present must be advertised by
	// the server.
	if out.IDTokenSignedResponseAlg != "" &&
		!slices.Contains(supportedIDTokenSigAlgs, out.IDTokenSignedResponseAlg) {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "id_token_signed_response_alg",
			"not in id_token_signing_alg_values_supported", "DCR-Vt011")
	}

	// request_object_* — Phase 1 rejects all three.
	if out.RequestObjectSigningAlg != "" {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "request_object_signing_alg",
			"request objects are not supported in Phase 1 DCR", "DCR-Vt012")
	}
	if out.RequestObjectEncryptionAlg != "" {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "request_object_encryption_alg",
			"request objects are not supported in Phase 1 DCR", "DCR-Vt013")
	}
	if out.RequestObjectEncryptionEnc != "" {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "request_object_encryption_enc",
			"request objects are not supported in Phase 1 DCR", "DCR-Vt014")
	}

	// redirect_uris count + per-URI compliance.
	if cfg.MaxRedirectURIs() > 0 && len(out.RedirectURIs) > cfg.MaxRedirectURIs() {
		return nil, newClampError(ErrCodeInvalidClientMetadata, "redirect_uris",
			fmt.Sprintf("exceeds MaxRedirectURIs (%d)", cfg.MaxRedirectURIs()), "DCR-Vt015")
	}
	if err := CheckRedirectURIs(cfg, out.ApplicationType, out.GrantTypes, out.TokenEndpointAuthMethod, out.RedirectURIs); err != nil {
		return nil, err
	}

	return &out, nil
}

// CheckRedirectURIs runs the redirect-URI compliance + host-pattern
// checks per cavekit-register-handler.md R4. Loopback HTTP URIs are
// accepted for `application_type=native` per the kit's "Loopback HTTP
// redirect URIs are accepted for native" AC (also covers T-035's
// `domain.GetOIDCV1Compliance` integration in the same code path).
//
// Returns *ClampError on failure; nil on success.
func CheckRedirectURIs(cfg DCRConfigSubset, appType string, grantTypes []string, authMethod string, uris []string) error {
	if len(uris) == 0 {
		// Empty redirect_uris is acceptable for grant types that don't
		// use them (e.g. device_code, client_credentials). The
		// per-grant compliance call below catches the cases where
		// redirect_uris is mandatory.
		return runOIDCV1Compliance(appType, grantTypes, authMethod, uris)
	}

	for _, raw := range uris {
		if strings.TrimSpace(raw) == "" {
			return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
				"contains an empty entry", "DCR-Vt020")
		}
		// cavekit-register-handler.md R4 amendment 2026-04-27 / F-100:
		// MUST parse via net/url and MUST reject any URL carrying
		// userinfo. The hand-rolled string-cut parser this replaced
		// missed the RFC 3986 userinfo segment, allowing
		// `https://victim.example.com:443@evil.com/cb` to satisfy
		// `*.example.com` while pointing at evil.com.
		parsed, perr := url.Parse(raw)
		if perr != nil || parsed == nil || parsed.Scheme == "" {
			return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
				"is not a valid URL: "+raw, "DCR-Vt023")
		}
		if parsed.User != nil {
			return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
				"MUST NOT carry userinfo (RFC 7591 / OAuth 2.1 §4.1.2): "+raw, "DCR-Vt024")
		}
		// cavekit-register-handler.md R4 amendment 2026-04-27 / F-218:
		// scheme allow-list. Hard-reject `javascript:`/`data:`/`vbscript:`/
		// `file:`/`about:`/`chrome:`/`chrome-extension:`/`ms-browser-extension:`
		// (XSS / file-disclosure vectors). For non-http(s), allow custom
		// schemes ONLY when application_type=native AND the scheme is a
		// reverse-domain identifier (matches `^[a-z][a-z0-9+.-]*$` AND
		// contains at least one `.`) per RFC 8252 §7.1.
		if err := checkRedirectURIScheme(parsed.Scheme, appType, raw); err != nil {
			return err
		}
		if isLoopbackHTTP(raw) && appType == "native" {
			// Loopback HTTP is allowed for native per RFC 8252 §7.3 and
			// the kit's R4 AC. Skip the host-pattern check for loopback
			// since the host is fixed by spec.
			continue
		}
		if patterns := cfg.AllowedRedirectURIHostPatterns(); len(patterns) > 0 {
			if !matchesAnyHostPattern(parsed, patterns) {
				return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
					"does not match DCR.AllowedRedirectURIHostPatterns: "+raw, "DCR-Vt021")
			}
		}
	}

	return runOIDCV1Compliance(appType, grantTypes, authMethod, uris)
}

// runOIDCV1Compliance invokes domain.GetOIDCV1Compliance on the
// converted enums and converts a non-compliant result into the RFC
// 7591 `invalid_redirect_uri` envelope. Per kit R4 AC: "Each
// redirect_uris entry passes domain.GetOIDCV1Compliance".
func runOIDCV1Compliance(appType string, grantTypes []string, authMethod string, uris []string) error {
	at := mapApplicationType(appType)
	gts := mapGrantTypes(grantTypes)
	am := mapAuthMethod(authMethod)
	c := domain.GetOIDCV1Compliance(at, gts, am, uris)
	if c == nil || !c.NoneCompliant {
		return nil
	}
	return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
		"OIDC v1 compliance failed: "+strings.Join(c.Problems, ", "), "DCR-Vt022")
}

// DCRConfigSubset is the slice of [DCRConfig] used by the DCR clamp
// path. Defined as an interface so unit tests can stub it without
// pulling in the full Server config tree, and so cavekit-manage-handler
// (T-054) can pass a different config source if/when per-org overrides
// land in Phase 2.
type DCRConfigSubset interface {
	AllowedGrantTypes() []string
	AllowedResponseTypes() []string
	AllowedAuthMethods() []string
	AllowedApplicationTypes() []string
	AllowedRedirectURIHostPatterns() []string
	MaxRedirectURIs() int
}

// helpers ----------------------------------------------------------

// canonicaliseResponseType normalises a response_type value (RFC 6749
// §3.1.1 space-separated set) into a stable canonical form: tokens
// split on whitespace, sorted alphabetically, joined with a single
// space. Empty / whitespace-only input returns "".
//
// The canonical form deliberately matches the upstream
// zitadel/oidc/v3 spelling (e.g. `ResponseTypeIDToken = "id_token
// token"`) — sorted alphabetical order — so this canonicalization
// produces the same string the rest of Zitadel's OIDC stack already
// switches on.
func canonicaliseResponseType(s string) string {
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return ""
	}
	slices.Sort(tokens)
	return strings.Join(tokens, " ")
}

// intersectResponseTypes is the canonicalization-aware variant of
// [intersectStringSlice] for `response_type` values. Both the
// requested values and the allow-list entries are canonicalized
// before equality. The output preserves the allow-list canonical
// spelling (since the allow-list is the operator-blessed form).
//
// cavekit-register-handler.md R4 amendment 2026-04-27 / F-103.
func intersectResponseTypes(requested, allowed []string) []string {
	if len(allowed) == 0 {
		return nil
	}
	// Pre-canonicalize the allow-list once so the inner loop is a
	// constant-cost map lookup.
	canonAllowed := make(map[string]string, len(allowed))
	for _, a := range allowed {
		canon := canonicaliseResponseType(a)
		if canon == "" {
			continue
		}
		// First-write-wins on duplicate canonical keys; the operator
		// gets back their first spelling.
		if _, exists := canonAllowed[canon]; !exists {
			canonAllowed[canon] = a
		}
	}
	out := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, r := range requested {
		canon := canonicaliseResponseType(r)
		if canon == "" {
			continue
		}
		if _, ok := canonAllowed[canon]; !ok {
			continue
		}
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canonAllowed[canon])
	}
	return out
}

func intersectStringSlice(requested, allowed []string) []string {
	if len(allowed) == 0 {
		return nil // empty allow-list is interpreted as "deny all" here;
		// callers that want "unrestricted" pass a non-empty list. The
		// cmd/defaults.yaml DCRConfig sets defaults for every clamp list
		// so this branch never fires in production.
	}
	out := make([]string, 0, len(requested))
	for _, r := range requested {
		if slices.Contains(allowed, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// isLoopbackHTTP returns true for `http://localhost[:port]/...`,
// `http://127.0.0.1[:port]/...`, `http://[::1][:port]/...` (RFC 8252
// §7.3 loopback IPs).
func isLoopbackHTTP(u string) bool {
	if !strings.HasPrefix(u, "http://") {
		return false
	}
	rest := strings.TrimPrefix(u, "http://")
	host, _, _ := strings.Cut(rest, "/")
	host, _, _ = strings.Cut(host, "?")
	// Strip optional :port. IPv6 must be in brackets.
	if strings.HasPrefix(host, "[") {
		closing := strings.Index(host, "]")
		if closing < 0 {
			return false
		}
		hostOnly := host[1:closing]
		return hostOnly == "::1"
	}
	hostOnly, _, _ := strings.Cut(host, ":")
	return hostOnly == "localhost" || hostOnly == "127.0.0.1"
}

// matchesAnyHostPattern checks whether the URL's host matches one of
// the configured patterns. Patterns support `*` as a single-label
// wildcard (e.g. `*.example.com` matches `app.example.com` but NOT
// `deep.app.example.com`) and exact-match for non-wildcard entries.
//
// The URL MUST already be parsed by [url.Parse] — passing the parsed
// struct rather than a raw string is the cavekit-register-handler.md
// R4 amendment 2026-04-27 contract that prevents the F-100 userinfo
// bypass. `u.Hostname()` correctly extracts the host even when
// userinfo is present (caller is expected to reject userinfo first).
func matchesAnyHostPattern(u *url.URL, patterns []string) bool {
	if u == nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	for _, p := range patterns {
		if hostMatches(host, p) {
			return true
		}
	}
	return false
}

func hostMatches(host, pattern string) bool {
	if pattern == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		// Single-label wildcard: host must end with suffix and have
		// exactly one extra label.
		if !strings.HasSuffix(host, suffix) {
			return false
		}
		left := strings.TrimSuffix(host, suffix)
		return left != "" && !strings.Contains(left, ".")
	}
	return false
}

// mapApplicationType / mapGrantTypes / mapAuthMethod convert the
// wire-string forms (RFC 7591 §2 vocabulary) to domain.OIDC*
// pointers/values for the existing compliance call. Unknown values
// map to nil so the compliance code-path can decide whether to
// require a specific value.
func mapApplicationType(s string) *domain.OIDCApplicationType {
	switch s {
	case "web":
		v := domain.OIDCApplicationTypeWeb
		return &v
	case "native":
		v := domain.OIDCApplicationTypeNative
		return &v
	case "browser", "user_agent":
		v := domain.OIDCApplicationTypeUserAgent
		return &v
	}
	return nil
}

func mapGrantTypes(ss []string) []domain.OIDCGrantType {
	out := make([]domain.OIDCGrantType, 0, len(ss))
	for _, s := range ss {
		switch s {
		case "authorization_code":
			out = append(out, domain.OIDCGrantTypeAuthorizationCode)
		case "implicit":
			out = append(out, domain.OIDCGrantTypeImplicit)
		case "refresh_token":
			out = append(out, domain.OIDCGrantTypeRefreshToken)
		case "urn:ietf:params:oauth:grant-type:device_code":
			out = append(out, domain.OIDCGrantTypeDeviceCode)
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			out = append(out, domain.OIDCGrantTypeTokenExchange)
		}
	}
	return out
}

func mapAuthMethod(s string) *domain.OIDCAuthMethodType {
	switch s {
	case "client_secret_basic":
		v := domain.OIDCAuthMethodTypeBasic
		return &v
	case "client_secret_post":
		v := domain.OIDCAuthMethodTypePost
		return &v
	case "none":
		v := domain.OIDCAuthMethodTypeNone
		return &v
	case "private_key_jwt":
		v := domain.OIDCAuthMethodTypePrivateKeyJWT
		return &v
	}
	return nil
}

// IsClampError reports whether err is a [*ClampError]. Convenience
// for HTTP handler bodies that need the RFC 7591 envelope code.
func IsClampError(err error) (*ClampError, bool) {
	var ce *ClampError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}

// hardRejectedSchemes carries schemes that are NEVER valid for an OAuth
// redirect URI per cavekit-register-handler.md R4 amendment 2026-04-27 /
// F-218. Lower-case keys; check is case-insensitive at the call site.
var hardRejectedSchemes = map[string]struct{}{
	"javascript":           {},
	"data":                 {},
	"vbscript":             {},
	"file":                 {},
	"about":                {},
	"chrome":               {},
	"chrome-extension":     {},
	"ms-browser-extension": {},
}

// schemePattern is the RFC 3986 §3.1 scheme syntax plus a lower-case
// requirement (we lower the input before matching). Reverse-domain
// custom schemes (RFC 8252 §7.1) ALSO require at least one `.`.
var schemePattern = regexp.MustCompile(`^[a-z][a-z0-9+.\-]*$`)

// checkRedirectURIScheme enforces the F-218 scheme allow-list:
//   - http / https accepted unconditionally.
//   - hardRejectedSchemes always rejected (even for native — the headline
//     attack is `redirect_uris=["javascript:..."]` for application_type=native).
//   - any other scheme accepted ONLY when appType == "native" AND the
//     scheme is reverse-domain shaped.
func checkRedirectURIScheme(scheme, appType, raw string) error {
	s := strings.ToLower(scheme)
	if _, blocked := hardRejectedSchemes[s]; blocked {
		return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
			"scheme "+scheme+" is not allowed (XSS / file-disclosure vector): "+raw,
			"DCR-Vt025")
	}
	if s == "http" || s == "https" {
		return nil
	}
	if appType != "native" {
		return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
			"custom scheme "+scheme+" is allowed only for application_type=native: "+raw,
			"DCR-Vt026")
	}
	if !schemePattern.MatchString(s) || !strings.Contains(s, ".") {
		return newClampError(ErrCodeInvalidRedirectURI, "redirect_uris",
			"custom scheme "+scheme+" is not a reverse-domain identifier (RFC 8252 §7.1): "+raw,
			"DCR-Vt027")
	}
	return nil
}
