package domain

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	http_util "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
)

const (
	httpScheme        = "http://"
	httpsScheme       = "https://"
	localhostHostname = "localhost"
)

type OIDCApp struct {
	models.ObjectRoot

	AppID                    string
	AppName                  string
	ClientID                 string
	EncodedHash              string
	ClientSecretString       string
	RedirectUris             []string
	ResponseTypes            []OIDCResponseType
	GrantTypes               []OIDCGrantType
	ApplicationType          *OIDCApplicationType
	AuthMethodType           *OIDCAuthMethodType
	PostLogoutRedirectUris   []string
	OIDCVersion              *OIDCVersion
	Compliance               *Compliance
	DevMode                  *bool
	AccessTokenType          *OIDCTokenType
	AccessTokenRoleAssertion *bool
	IDTokenRoleAssertion     *bool
	IDTokenUserinfoAssertion *bool
	ClockSkew                *time.Duration
	AdditionalOrigins        []string
	SkipNativeAppSuccessPage *bool
	BackChannelLogoutURI     *string
	LoginVersion             *LoginVersion
	LoginBaseURI             *string

	State AppState
}

func (a *OIDCApp) GetApplicationName() string {
	return a.AppName
}

func (a *OIDCApp) GetState() AppState {
	return a.State
}

func (a *OIDCApp) setClientID(clientID string) {
	a.ClientID = clientID
}

func (a *OIDCApp) setClientSecret(encodedHash string) {
	a.EncodedHash = encodedHash
}

func (a *OIDCApp) requiresClientSecret() bool {
	return a.AuthMethodType != nil && (*a.AuthMethodType == OIDCAuthMethodTypeBasic || *a.AuthMethodType == OIDCAuthMethodTypePost)
}

type OIDCVersion int32

const (
	OIDCVersionV1 OIDCVersion = iota
)

type OIDCResponseType int32

const (
	OIDCResponseTypeUnspecified OIDCResponseType = iota - 1 // Negative offset not to break existing configs.
	OIDCResponseTypeCode
	OIDCResponseTypeIDToken
	OIDCResponseTypeIDTokenToken
)

//go:generate enumer -type OIDCResponseMode -transform snake -trimprefix OIDCResponseMode
type OIDCResponseMode int

const (
	OIDCResponseModeUnspecified OIDCResponseMode = iota
	OIDCResponseModeQuery
	OIDCResponseModeFragment
	OIDCResponseModeFormPost
)

type OIDCGrantType int32

const (
	OIDCGrantTypeAuthorizationCode OIDCGrantType = iota
	OIDCGrantTypeImplicit
	OIDCGrantTypeRefreshToken
	OIDCGrantTypeDeviceCode
	OIDCGrantTypeTokenExchange
)

type OIDCApplicationType int32

const (
	OIDCApplicationTypeWeb OIDCApplicationType = iota
	OIDCApplicationTypeUserAgent
	OIDCApplicationTypeNative
)

type OIDCAuthMethodType int32

const (
	OIDCAuthMethodTypeBasic OIDCAuthMethodType = iota
	OIDCAuthMethodTypePost
	OIDCAuthMethodTypeNone
	OIDCAuthMethodTypePrivateKeyJWT
)

type Compliance struct {
	NoneCompliant bool
	Problems      []string
}

type OIDCTokenType int32

const (
	OIDCTokenTypeBearer OIDCTokenType = iota
	OIDCTokenTypeJWT
)

func (a *OIDCApp) IsValid() bool {
	if (a.ClockSkew != nil && (*a.ClockSkew > time.Second*5 || *a.ClockSkew < time.Second*0)) || !a.OriginsValid() {
		return false
	}
	grantTypes := a.getRequiredGrantTypes()
	if len(grantTypes) == 0 {
		return false
	}
	for _, grantType := range grantTypes {
		ok := containsOIDCGrantType(a.GrantTypes, grantType)
		if !ok {
			return false
		}
	}
	return true
}

func (a *OIDCApp) OriginsValid() bool {
	for _, origin := range a.AdditionalOrigins {
		if !http_util.IsOrigin(strings.TrimSpace(origin)) {
			return false
		}
	}
	return true
}

func ContainsRequiredGrantTypes(responseTypes []OIDCResponseType, grantTypes []OIDCGrantType) bool {
	required := RequiredOIDCGrantTypes(responseTypes, grantTypes)
	return ContainsOIDCGrantTypes(required, grantTypes)
}

func RequiredOIDCGrantTypes(responseTypes []OIDCResponseType, grantTypesSet []OIDCGrantType) (grantTypes []OIDCGrantType) {
	var implicit bool

	for _, r := range responseTypes {
		switch r {
		case OIDCResponseTypeCode:
			// #5684 when "Device Code" is selected, "Authorization Code" is no longer a hard requirement
			if !containsOIDCGrantType(grantTypesSet, OIDCGrantTypeDeviceCode) {
				grantTypes = append(grantTypes, OIDCGrantTypeAuthorizationCode)
			} else {
				grantTypes = append(grantTypes, OIDCGrantTypeDeviceCode)
			}
		case OIDCResponseTypeIDToken, OIDCResponseTypeIDTokenToken:
			if !implicit {
				implicit = true
				grantTypes = append(grantTypes, OIDCGrantTypeImplicit)
			}
		}
	}

	return grantTypes
}

func (a *OIDCApp) getRequiredGrantTypes() []OIDCGrantType {
	return RequiredOIDCGrantTypes(a.ResponseTypes, a.GrantTypes)
}

func ContainsOIDCGrantTypes(shouldContain, list []OIDCGrantType) bool {
	for _, should := range shouldContain {
		if !containsOIDCGrantType(list, should) {
			return false
		}
	}
	return true
}

func containsOIDCGrantType(grantTypes []OIDCGrantType, grantType OIDCGrantType) bool {
	return slices.Contains(grantTypes, grantType)
}

func (a *OIDCApp) FillCompliance() {
	a.Compliance = GetOIDCCompliance(a.OIDCVersion, a.ApplicationType, a.GrantTypes, a.ResponseTypes, a.AuthMethodType, a.RedirectUris)
}

func GetOIDCCompliance(version *OIDCVersion, appType *OIDCApplicationType, grantTypes []OIDCGrantType, responseTypes []OIDCResponseType, authMethod *OIDCAuthMethodType, redirectUris []string) *Compliance {
	if version != nil && *version == OIDCVersionV1 {
		return GetOIDCV1Compliance(appType, grantTypes, authMethod, redirectUris)
	}

	return &Compliance{
		NoneCompliant: true,
		Problems:      []string{"Application.OIDC.UnsupportedVersion"},
	}
}

func GetOIDCV1Compliance(appType *OIDCApplicationType, grantTypes []OIDCGrantType, authMethod *OIDCAuthMethodType, redirectUris []string) *Compliance {
	compliance := &Compliance{NoneCompliant: false}

	checkGrantTypesCombination(compliance, grantTypes)
	checkRedirectURIs(compliance, grantTypes, appType, redirectUris)
	checkApplicationType(compliance, appType, authMethod)

	if compliance.NoneCompliant {
		compliance.Problems = append([]string{"Application.OIDC.V1.NotCompliant"}, compliance.Problems...)
	}
	return compliance
}

func checkGrantTypesCombination(compliance *Compliance, grantTypes []OIDCGrantType) {
	if !containsOIDCGrantType(grantTypes, OIDCGrantTypeDeviceCode) && containsOIDCGrantType(grantTypes, OIDCGrantTypeRefreshToken) && !containsOIDCGrantType(grantTypes, OIDCGrantTypeAuthorizationCode) {
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.GrantType.Refresh.NoAuthCode")
	}
}

func checkRedirectURIs(compliance *Compliance, grantTypes []OIDCGrantType, appType *OIDCApplicationType, redirectUris []string) {
	// See #5684 for OIDCGrantTypeDeviceCode and redirectUris further explanation
	if len(redirectUris) == 0 && (!containsOIDCGrantType(grantTypes, OIDCGrantTypeDeviceCode) || (containsOIDCGrantType(grantTypes, OIDCGrantTypeDeviceCode) && containsOIDCGrantType(grantTypes, OIDCGrantTypeAuthorizationCode))) {
		compliance.NoneCompliant = true
		compliance.Problems = append([]string{"Application.OIDC.V1.NoRedirectUris"}, compliance.Problems...)
	}

	if containsOIDCGrantType(grantTypes, OIDCGrantTypeImplicit) && containsOIDCGrantType(grantTypes, OIDCGrantTypeAuthorizationCode) {
		CheckRedirectUrisImplicitAndCode(compliance, appType, redirectUris)
	} else {
		if containsOIDCGrantType(grantTypes, OIDCGrantTypeImplicit) {
			CheckRedirectUrisImplicit(compliance, appType, redirectUris)
		}
		if containsOIDCGrantType(grantTypes, OIDCGrantTypeAuthorizationCode) {
			CheckRedirectUrisCode(compliance, appType, redirectUris)
		}
	}
}

func checkApplicationType(compliance *Compliance, appType *OIDCApplicationType, authMethod *OIDCAuthMethodType) {
	if appType != nil {
		switch *appType {
		case OIDCApplicationTypeNative:
			GetOIDCV1NativeApplicationCompliance(compliance, authMethod)
		case OIDCApplicationTypeUserAgent:
			GetOIDCV1UserAgentApplicationCompliance(compliance, authMethod)
		case OIDCApplicationTypeWeb:
			return
		}
	}

	if compliance.NoneCompliant {
		compliance.Problems = append([]string{"Application.OIDC.V1.NotCompliant"}, compliance.Problems...)
	}
}

func GetOIDCV1NativeApplicationCompliance(compliance *Compliance, authMethod *OIDCAuthMethodType) {
	if authMethod != nil && *authMethod != OIDCAuthMethodTypeNone {
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Native.AuthMethodType.NotNone")
	}
}

func GetOIDCV1UserAgentApplicationCompliance(compliance *Compliance, authMethod *OIDCAuthMethodType) {
	if authMethod != nil && *authMethod != OIDCAuthMethodTypeNone {
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.UserAgent.AuthMethodType.NotNone")
	}
}

func CheckRedirectUrisCode(compliance *Compliance, appType *OIDCApplicationType, redirectUris []string) {
	if urlsAreHttps(redirectUris) {
		return
	}
	if urlContainsPrefix(redirectUris, httpScheme) {
		if appType != nil && *appType == OIDCApplicationTypeUserAgent {
			compliance.NoneCompliant = true
			compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Code.RedirectUris.HttpOnlyForWeb")
		}
		if appType != nil && *appType == OIDCApplicationTypeNative && !onlyLocalhostIsHttp(redirectUris) {
			compliance.NoneCompliant = true
			compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Native.RedirectUris.MustBeHttpLocalhost")
		}
	}
	if containsCustom(redirectUris) && appType != nil && *appType != OIDCApplicationTypeNative {
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Code.RedirectUris.CustomOnlyForNative")
	}
}

func CheckRedirectUrisImplicit(compliance *Compliance, appType *OIDCApplicationType, redirectUris []string) {
	if urlsAreHttps(redirectUris) {
		return
	}
	if containsCustom(redirectUris) {
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Implicit.RedirectUris.CustomNotAllowed")
	}
	if urlContainsPrefix(redirectUris, httpScheme) {
		if appType != nil && *appType == OIDCApplicationTypeNative {
			if !onlyLocalhostIsHttp(redirectUris) {
				compliance.NoneCompliant = true
				compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Native.RedirectUris.MustBeHttpLocalhost")
			}
			return
		}
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Implicit.RedirectUris.HttpNotAllowed")
	}
}

func CheckRedirectUrisImplicitAndCode(compliance *Compliance, appType *OIDCApplicationType, redirectUris []string) {
	if urlsAreHttps(redirectUris) {
		return
	}
	if containsCustom(redirectUris) && appType != nil && *appType != OIDCApplicationTypeNative {
		compliance.NoneCompliant = true
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Implicit.RedirectUris.CustomNotAllowed")
	}
	if urlContainsPrefix(redirectUris, httpScheme) {
		if appType != nil && *appType == OIDCApplicationTypeUserAgent {
			compliance.NoneCompliant = true
			compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Code.RedirectUris.HttpOnlyForWeb")
		}
		if !onlyLocalhostIsHttp(redirectUris) && appType != nil && *appType == OIDCApplicationTypeNative {
			compliance.NoneCompliant = true
			compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.Native.RedirectUris.MustBeHttpLocalhost")
		}
	}
	if !compliance.NoneCompliant {
		compliance.Problems = append(compliance.Problems, "Application.OIDC.V1.NotAllCombinationsAreAllowed")
	}
}

func urlsAreHttps(uris []string) bool {
	for _, uri := range uris {
		if !strings.HasPrefix(uri, httpsScheme) {
			return false
		}
	}
	return true
}

func urlContainsPrefix(uris []string, prefix string) bool {
	for _, uri := range uris {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

func containsCustom(uris []string) bool {
	for _, uri := range uris {
		if !strings.HasPrefix(uri, httpScheme) && !strings.HasPrefix(uri, httpsScheme) {
			return true
		}
	}
	return false
}

// onlyLocalhostIsHttp returns true if:
//
//   - input string slice is empty
//   - all parseable URIs with scheme `http` in the string slice are localhost/loopback URIs (in all possible forms)
//
// It will return false if:
//   - any of the input URIs cannot be parsed
//   - any of the parseable input URIs with scheme `http` is not localhost/loopback
func onlyLocalhostIsHttp(uris []string) bool {
	for _, uri := range uris {
		url, err := url.ParseRequestURI(uri)

		if err != nil {
			return false
		}

		if url.Scheme == "http" {
			hostname := url.Hostname()

			if hostname == localhostHostname {
				continue
			}

			address, err := netip.ParseAddr(hostname)

			if err != nil {
				return false
			}

			if address.IsLoopback() {
				continue
			}

			return false
		}
	}
	return true
}

func OIDCOriginAllowList(redirectURIs, additionalOrigins []string) ([]string, error) {
	allowList := make([]string, 0)
	for _, redirect := range redirectURIs {
		origin, err := http_util.GetOriginFromURLString(redirect)
		if err != nil {
			return nil, err
		}
		if !http_util.IsOriginAllowed(allowList, origin) {
			allowList = append(allowList, origin)
		}
	}
	for _, origin := range additionalOrigins {
		if !http_util.IsOriginAllowed(allowList, origin) {
			allowList = append(allowList, origin)
		}
	}
	return allowList, nil
}

// OIDCAppFromRFC7591Metadata maps clamped RFC 7591 client metadata to
// an [OIDCApp] for the dynamic client registration flow
// (cavekit-register-handler.md R6 / T-039).
//
// Caller MUST have already passed the input through
// `internal/api/oidc/dcr.ValidateAndClampMetadata` (T-034) — this
// function performs only structural conversion (string vocabulary →
// domain enums), not validation. Unknown vocabulary values panic the
// caller would have rejected by clamp, but to keep the function pure
// here we simply skip them; an unknown auth_method or application_type
// produces a nil pointer (which downstream code already tolerates).
//
// The function is intentionally placed in `internal/domain/` so that
// other surfaces (RFC 7592 PUT in T-054, future per-org overrides) can
// reuse it without importing `internal/api/oidc/dcr`. Bridging from
// the wire-format `RFC7591Metadata` struct to this primitives-based
// signature lives at the dcr package boundary.
//
// Pass-through RFC 7591 fields not present in [OIDCApp] (`contacts`,
// `logo_uri`, etc.) are NOT handled here — T-040 routes them into the
// `dcr_meta` JSONB column via the parallel `dcr.BuildDCRMeta` helper.
//
// `OIDCVersion` is set to V1 because Phase 1 DCR only emits OIDC v1
// applications (cavekit-overview.md / kit out-of-scope: OIDC v2).
func OIDCAppFromRFC7591Metadata(
	clientName string,
	redirectURIs []string,
	grantTypes []string,
	responseTypes []string,
	tokenEndpointAuthMethod string,
	applicationType string,
	postLogoutRedirectURIs []string,
	backChannelLogoutURI string,
) *OIDCApp {
	app := &OIDCApp{
		AppName:                clientName,
		RedirectUris:           redirectURIs,
		PostLogoutRedirectUris: postLogoutRedirectURIs,
		GrantTypes:             rfc7591GrantTypes(grantTypes),
		ResponseTypes:          rfc7591ResponseTypes(responseTypes),
		AuthMethodType:         rfc7591AuthMethod(tokenEndpointAuthMethod),
		ApplicationType:        rfc7591ApplicationType(applicationType),
	}
	v := OIDCVersionV1
	app.OIDCVersion = &v
	if backChannelLogoutURI != "" {
		bcl := backChannelLogoutURI
		app.BackChannelLogoutURI = &bcl
	}
	return app
}

func rfc7591GrantTypes(ss []string) []OIDCGrantType {
	out := make([]OIDCGrantType, 0, len(ss))
	for _, s := range ss {
		switch s {
		case "authorization_code":
			out = append(out, OIDCGrantTypeAuthorizationCode)
		case "implicit":
			out = append(out, OIDCGrantTypeImplicit)
		case "refresh_token":
			out = append(out, OIDCGrantTypeRefreshToken)
		case "urn:ietf:params:oauth:grant-type:device_code":
			out = append(out, OIDCGrantTypeDeviceCode)
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			out = append(out, OIDCGrantTypeTokenExchange)
		}
	}
	return out
}

func rfc7591ResponseTypes(ss []string) []OIDCResponseType {
	out := make([]OIDCResponseType, 0, len(ss))
	for _, s := range ss {
		switch s {
		case "code":
			out = append(out, OIDCResponseTypeCode)
		case "id_token":
			out = append(out, OIDCResponseTypeIDToken)
		case "id_token token":
			out = append(out, OIDCResponseTypeIDTokenToken)
		}
	}
	return out
}

func rfc7591AuthMethod(s string) *OIDCAuthMethodType {
	var v OIDCAuthMethodType
	switch s {
	case "client_secret_basic":
		v = OIDCAuthMethodTypeBasic
	case "client_secret_post":
		v = OIDCAuthMethodTypePost
	case "none":
		v = OIDCAuthMethodTypeNone
	case "private_key_jwt":
		v = OIDCAuthMethodTypePrivateKeyJWT
	default:
		return nil
	}
	return &v
}

func rfc7591ApplicationType(s string) *OIDCApplicationType {
	var v OIDCApplicationType
	switch s {
	case "web":
		v = OIDCApplicationTypeWeb
	case "native":
		v = OIDCApplicationTypeNative
	case "browser", "user_agent":
		v = OIDCApplicationTypeUserAgent
	default:
		return nil
	}
	return &v
}
