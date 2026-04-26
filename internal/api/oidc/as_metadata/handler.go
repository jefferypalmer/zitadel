// Package as_metadata implements the RFC 8414 OAuth 2.0 Authorization
// Server Metadata handler at `/.well-known/oauth-authorization-server`.
//
// This is one of two well-known endpoints that signal DCR / MCP
// readiness to clients (the other is OIDC discovery, T-029). RFC 8414
// metadata is a strict subset of OIDC discovery; the two MUST agree on
// shared field values per cavekit-discovery-and-as-metadata.md R3.
//
// The handler is mounted ONLY when the yaml gate (config.OIDC.DCR.Enabled)
// is satisfied at startup. When mounted, the runtime feature flag still
// governs whether `registration_endpoint` appears in the body
// (cavekit-discovery-and-as-metadata.md R1 dual-gate); when not mounted,
// the request returns the mux-level 404 (R2 AC: "DCR.Enabled=false → 404").
package as_metadata

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// HandlerPath is the URL path the AS metadata handler responds at.
// Per RFC 8414 §3 the document MUST be served at hostname root —
// subpath deployments break Claude Code MCP probing
// (cavekit-discovery-and-as-metadata.md R4 / T-030).
const HandlerPath = "/.well-known/oauth-authorization-server"

// Metadata is the RFC 8414 §2 Authorization Server Metadata document.
// Field names + JSON tags match the spec verbatim. The struct is a
// strict subset of `oidc.DiscoveryConfiguration` for the fields shared
// between RFC 8414 and OIDC Discovery (R3 byte-identity for shared
// fields is enforced by the test harness).
type Metadata struct {
	Issuer                            string             `json:"issuer"`
	AuthorizationEndpoint             string             `json:"authorization_endpoint"`
	TokenEndpoint                     string             `json:"token_endpoint,omitempty"`
	JwksURI                           string             `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string             `json:"registration_endpoint,omitempty"`
	ResponseTypesSupported            []string           `json:"response_types_supported"`
	ResponseModesSupported            []string           `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []oidc.GrantType   `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []oidc.AuthMethod  `json:"token_endpoint_auth_methods_supported,omitempty"`
	ScopesSupported                   []string           `json:"scopes_supported,omitempty"`
	CodeChallengeMethodsSupported     []oidc.CodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
	RevocationEndpoint                string             `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string             `json:"introspection_endpoint,omitempty"`
}

// MetadataBuilder produces an [Metadata] document for the given context.
// The OIDC Server implements this signature (see
// internal/api/oidc/server.go AsMetadata).
type MetadataBuilder func(ctx context.Context) *Metadata

// NewHandler returns the http.Handler for [HandlerPath]. The builder is
// called once per request — it must be safe to call concurrently.
func NewHandler(build MetadataBuilder) http.Handler {
	w := newIssuerWarner()
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		md := build(ctx)

		// R4 hostname-root warning: log once per (instanceID, issuer)
		// when the issuer carries a non-root path component. Non-blocking;
		// the response still serves the metadata reflecting the observed
		// issuer.
		w.maybeWarn(ctx, md.Issuer)

		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
		// RFC 8414 §3 SHOULD: cache control for metadata documents is
		// implementation-defined; mirror OIDC discovery practice and
		// allow clients to cache briefly. No-store would break the spec
		// intent; use no-cache so clients revalidate but can serve
		// stale-while-revalidate.
		rw.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(rw).Encode(md)
	})
}

// issuerWarner emits a one-time WARN per (instanceID, issuer) pair when
// the observed issuer has a non-root URL path. The cache is sync.Map
// keyed on `instanceID + "\x00" + issuer` (separator is a forbidden
// URL character so collision is structurally impossible).
type issuerWarner struct {
	seen sync.Map // map[string]struct{}
}

func newIssuerWarner() *issuerWarner { return &issuerWarner{} }

func (w *issuerWarner) maybeWarn(ctx context.Context, issuer string) {
	if issuer == "" {
		return
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return
	}
	// Root: empty path or single "/" only.
	if u.Path == "" || u.Path == "/" {
		return
	}
	instanceID := authz.GetInstance(ctx).InstanceID()
	key := instanceID + "\x00" + issuer
	if _, loaded := w.seen.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	probe := u.Scheme + "://" + u.Host + HandlerPath
	logging.WithFields(
		"instance_id", instanceID,
		"observed_issuer", issuer,
		"probe_url", probe,
	).Warn(
		"OIDC.DCR.Enabled=true and the request issuer has a non-root URL path. " +
			"RFC 8414 / Claude Code MCP probe `.well-known/oauth-authorization-server` " +
			"at the hostname ROOT, not under a subpath — those clients will not " +
			"discover this DCR endpoint. See the deployment guide (hostname-root " +
			"requirement).")
}

// IsRootIssuer reports whether the given issuer URL is at hostname root
// (no path component or just "/"). Exported so tests + the integration
// suite can pin the predicate without re-parsing.
func IsRootIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return u.Path == "" || strings.TrimRight(u.Path, "/") == ""
}
