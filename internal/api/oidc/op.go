package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/backend/v3/instrumentation/metrics"
	"github.com/zitadel/zitadel/internal/api/assets"
	http_utils "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/api/ui/login"
	"github.com/zitadel/zitadel/internal/auth/repository"
	"github.com/zitadel/zitadel/internal/cache"
	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain/federatedlogout"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/notification/handlers"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/zerrors"
)

type Config struct {
	CodeMethodS256                    bool
	AuthMethodPost                    bool
	AuthMethodPrivateKeyJWT           bool
	GrantTypeRefreshToken             bool
	RequestObjectSupported            bool
	DefaultAccessTokenLifetime        time.Duration
	DefaultIdTokenLifetime            time.Duration
	DefaultRefreshTokenIdleExpiration time.Duration
	DefaultRefreshTokenExpiration     time.Duration
	JWKSCacheControlMaxAge            time.Duration
	CustomEndpoints                   *EndpointConfig
	DeviceAuth                        *DeviceAuthorizationConfig
	DefaultLoginURLV2                 string
	DefaultLogoutURLV2                string
	PublicKeyCacheMaxAge              time.Duration
	DefaultBackChannelLogoutLifetime  time.Duration
	BackChannelLogout                 handlers.BackChannelLogoutWorkerConfig
	DCR                               DCRConfig
}

// DCRConfig is the runtime configuration for Dynamic Client Registration
// (RFC 7591 / RFC 7592 / RFC 8707). The yaml block at OIDC.DCR populates
// this; see cmd/defaults.yaml.
//
// Dual-gate: mounting of /oidc/v1/register{/*} and advertisement of
// `registration_endpoint` in discovery / RFC 8414 AS metadata require
// BOTH DCR.Enabled=true (startup / yaml) AND the runtime feature flag
// feature.KeyDynamicClientRegistration=true per instance.
type DCRConfig struct {
	Enabled                        bool
	RequireInitialAccessToken      bool
	DefaultProjectID               string
	DefaultOrgID                   string
	MaxRedirectURIs                int
	MaxRequestBodyBytes            int64
	AllowedGrantTypes              []string
	AllowedResponseTypes           []string
	AllowedAuthMethods             []string
	AllowedApplicationTypes        []string
	AllowedRedirectURIHostPatterns []string
	AllowedAudiences               []string
	RegistrationAccessToken        DCRRegistrationAccessTokenConfig
	InitialAccessToken             DCRInitialAccessTokenConfig
	SoftwareStatement              DCRSoftwareStatementConfig
	ClientSecretExpiresIn          time.Duration
	JwksURI                        DCRJwksURIConfig
	// Janitor controls the periodic reaper that prunes expired
	// software_statement (iss, jti) replay-dedupe rows from
	// projections.dcr_software_statement_jtis1. cavekit-software-
	// statement.md R9.
	Janitor DCRJanitorConfig
}

// DCRJanitorConfig configures the software_statement JTI reaper goroutine
// started alongside `serviceping.Start` in cmd/start/start.go.
// Enabled defaults to true; Interval defaults to 1h. Env-var bindings:
// ZITADEL_OIDC_DCR_JANITOR_ENABLED, ZITADEL_OIDC_DCR_JANITOR_INTERVAL.
type DCRJanitorConfig struct {
	Enabled  bool
	Interval time.Duration
}

type DCRRegistrationAccessTokenConfig struct {
	Enabled  bool
	Lifetime time.Duration
}

type DCRInitialAccessTokenConfig struct {
	DefaultLifetime time.Duration
	DefaultMaxUses  int
}

type DCRSoftwareStatementConfig struct {
	Enabled            bool
	TrustedIssuers     []DCRTrustedIssuer
	JWKSCacheTTL       time.Duration
	AllowedAlgorithms  []string
	JTIRetentionBuffer time.Duration
	// SkipAudValidation reverts to Phase 2 status quo (no aud check)
	// per cavekit-software-statement.md R13 — default false; binds to
	// ZITADEL_OIDC_DCR_SOFTWARESTATEMENT_SKIPAUDVALIDATION.
	SkipAudValidation bool
}

// DCRTrustedIssuer is one entry in `OIDC.DCR.SoftwareStatement.TrustedIssuers`.
// `Issuer` is the absolute https URL claimed in the JWT `iss` header (matched
// case-sensitively at request time). `JWKSURI`, when empty, triggers OIDC
// discovery against `${Issuer}/.well-known/openid-configuration`. When non-empty
// it overrides discovery and MUST also be https. `RequiredClaims` is a list of
// JWT claim names (atop the standard JWT claims of cavekit-software-statement.md
// R5) that MUST be present and non-empty in the body.
type DCRTrustedIssuer struct {
	Issuer         string
	JWKSURI        string
	RequiredClaims []string
}

type DCRJwksURIConfig struct {
	HTTPTimeout        time.Duration
	AllowLoopbackInDev bool
	DisallowedIPRanges []string
}

// DCRClampAdapter wraps DCRConfig to satisfy `dcr.DCRConfigSubset`
// (the metadata clamp interface) without requiring the dcr package
// to import this one — keeps the import graph one-way (start.go →
// dcr, not dcr → oidc package). The adapter is a thin pass-through;
// it allocates nothing and is safe to construct per request if
// needed.
type DCRClampAdapter struct {
	C *DCRConfig
}

func (a DCRClampAdapter) AllowedGrantTypes() []string       { return a.C.AllowedGrantTypes }
func (a DCRClampAdapter) AllowedResponseTypes() []string    { return a.C.AllowedResponseTypes }
func (a DCRClampAdapter) AllowedAuthMethods() []string      { return a.C.AllowedAuthMethods }
func (a DCRClampAdapter) AllowedApplicationTypes() []string { return a.C.AllowedApplicationTypes }
func (a DCRClampAdapter) AllowedRedirectURIHostPatterns() []string {
	return a.C.AllowedRedirectURIHostPatterns
}
func (a DCRClampAdapter) MaxRedirectURIs() int { return a.C.MaxRedirectURIs }

// DCRAnonAdapter wraps DCRConfig to satisfy `dcr.AnonymousConfig`
// for the anonymous-mode resolution path
// (cavekit-register-handler.md R3 AC4-AC5 / T-038).
type DCRAnonAdapter struct {
	C *DCRConfig
}

func (a DCRAnonAdapter) RequireInitialAccessToken() bool { return a.C.RequireInitialAccessToken }
func (a DCRAnonAdapter) DefaultOrgID() string            { return a.C.DefaultOrgID }
func (a DCRAnonAdapter) DefaultProjectID() string        { return a.C.DefaultProjectID }

// BackChannelLogoutConfig returns the BackChannelLogoutWorkerConfig and takes the deprecated TokenLifetime into account.
func (c *Config) BackChannelLogoutConfig() *handlers.BackChannelLogoutWorkerConfig {
	if c.DefaultBackChannelLogoutLifetime == 0 {
		return &c.BackChannelLogout
	}
	c.BackChannelLogout.TokenLifetime = c.DefaultBackChannelLogoutLifetime
	return &c.BackChannelLogout
}

type EndpointConfig struct {
	Auth          *Endpoint
	Token         *Endpoint
	Introspection *Endpoint
	Userinfo      *Endpoint
	Revocation    *Endpoint
	EndSession    *Endpoint
	Keys          *Endpoint
	DeviceAuth    *Endpoint
}

type Endpoint struct {
	Path string
	URL  string
}

type OPStorage struct {
	repo                              repository.Repository
	command                           *command.Commands
	query                             *query.Queries
	eventstore                        *eventstore.Eventstore
	defaultLoginURL                   string
	defaultLoginURLV2                 string
	defaultLogoutURLV2                string
	defaultAccessTokenLifetime        time.Duration
	defaultIdTokenLifetime            time.Duration
	defaultRefreshTokenIdleExpiration time.Duration
	defaultRefreshTokenExpiration     time.Duration
	authAlg                           crypto.AuthAlgorithm
	assetAPIPrefix                    func(ctx context.Context) string
	contextToIssuer                   func(context.Context) string
	federateLogoutCache               cache.Cache[federatedlogout.Index, string, *federatedlogout.FederatedLogout]
}

// Provider is used to overload certain [op.Provider] methods
type Provider struct {
	*op.Provider
	accessTokenKeySet oidc.KeySet
	idTokenHintKeySet oidc.KeySet
}

// IDTokenHintVerifier configures a Verifier and supported signing algorithms based on the Web Key feature in the context.
func (o *Provider) IDTokenHintVerifier(ctx context.Context) *op.IDTokenHintVerifier {
	return op.NewIDTokenHintVerifier(op.IssuerFromContext(ctx), o.idTokenHintKeySet, op.WithSupportedIDTokenHintSigningAlgorithms(
		supportedSigningAlgs()...,
	))
}

// AccessTokenVerifier configures a Verifier and supported signing algorithms based on the Web Key feature in the context.
func (o *Provider) AccessTokenVerifier(ctx context.Context) *op.AccessTokenVerifier {
	return op.NewAccessTokenVerifier(op.IssuerFromContext(ctx), o.accessTokenKeySet, op.WithSupportedAccessTokenSigningAlgorithms(
		supportedSigningAlgs()...,
	))
}

func NewServer(
	ctx context.Context,
	config Config,
	defaultLogoutRedirectURI string,
	externalSecure bool,
	command *command.Commands,
	query *query.Queries,
	repo repository.Repository,
	authAlg crypto.AuthAlgorithm,
	targetEncryptionAlgorithm crypto.EncryptionAlgorithm,
	cryptoKey []byte,
	es *eventstore.Eventstore,
	userAgentCookie, instanceHandler func(http.Handler) http.Handler,
	accessHandler *middleware.AccessInterceptor,
	fallbackLogger *slog.Logger,
	hashConfig crypto.HashConfig,
	federatedLogoutCache cache.Cache[federatedlogout.Index, string, *federatedlogout.FederatedLogout],
) (*Server, error) {
	opConfig, err := createOPConfig(config, defaultLogoutRedirectURI, cryptoKey)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "OIDC-EGrqd", "cannot create op config: %w")
	}
	storage := newStorage(config, command, query, repo, authAlg, es, ContextToIssuer, federatedLogoutCache)
	keyCache := newPublicKeyCache(ctx, config.PublicKeyCacheMaxAge, queryKeyFunc(query))
	accessTokenKeySet := newOidcKeySet(keyCache, withKeyExpiryCheck(true))
	idTokenHintKeySet := newOidcKeySet(keyCache)

	alg := op.NewAES256GCMCrypto(opConfig.CryptoKey, "")
	if authAlg.LegacyTokenEnabled() {
		alg = op.NewCompositeCrypto(
			alg,
			[]op.Decrypter{
				alg,
				op.NewAESCrypto(opConfig.CryptoKey),
			},
		)
	}
	options := []op.Option{
		op.WithCrypto(alg),
	}
	if !externalSecure {
		options = append(options, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(
		opConfig,
		storage,
		IssuerFromContext,
		options...,
	)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "OIDC-DAtg3", "cannot create provider")
	}
	hasher, err := hashConfig.NewHasher()
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "OIDC-Aij4e", "cannot create secret hasher")
	}
	server := &Server{
		LegacyServer: op.NewLegacyServer(&Provider{
			Provider:          provider,
			accessTokenKeySet: accessTokenKeySet,
			idTokenHintKeySet: idTokenHintKeySet,
		}, endpoints(config.CustomEndpoints)),
		repo:                       repo,
		query:                      query,
		command:                    command,
		accessTokenKeySet:          accessTokenKeySet,
		idTokenHintKeySet:          idTokenHintKeySet,
		defaultLoginURL:            fmt.Sprintf("%s%s?%s=", login.HandlerPrefix, login.EndpointLogin, login.QueryAuthRequestID),
		defaultLoginURLV2:          config.DefaultLoginURLV2,
		defaultLogoutURLV2:         config.DefaultLogoutURLV2,
		defaultAccessTokenLifetime: config.DefaultAccessTokenLifetime,
		defaultIdTokenLifetime:     config.DefaultIdTokenLifetime,
		jwksCacheControlMaxAge:     config.JWKSCacheControlMaxAge,
		fallbackLogger:             fallbackLogger,
		hasher:                     hasher,
		encAlg:                     authAlg,
		targetEncryptionAlgorithm:  targetEncryptionAlgorithm,
		opCrypto:                   alg,
		assetAPIPrefix:             assets.AssetAPI(),
		dcrEnabled:                 config.DCR.Enabled,
	}
	metricTypes := []metrics.MetricType{metrics.MetricTypeRequestCount, metrics.MetricTypeStatusCode, metrics.MetricTypeTotalCount}
	server.Handler = op.RegisterLegacyServer(server,
		server.authorizeCallbackHandler,
		op.WithFallbackLogger(fallbackLogger),
		op.WithHTTPMiddleware(
			middleware.CallDurationHandler,
			middleware.RequestDetailsHandler(),
			middleware.MetricsHandler(metricTypes),
			middleware.TraceHandler(),
			middleware.LogHandler("oidc"),
			middleware.RecoverHandler(writeRecoverError),
			middleware.NoCacheInterceptor().Handler,
			instanceHandler,
			userAgentCookie,
			http_utils.CopyHeadersToContext,
			// RFC 8707 sidecar: captures `resource` form values into ctx
			// so the /authorize converter can read them without needing
			// upstream AuthRequest.Resource (cavekit-rfc8707-resource.md R7).
			// Also validates against config.DCR.AllowedAudiences and emits
			// `invalid_target` 400 on rejection (R3/R6, T-026/T-028).
			NewAuthorizeResourceSidecar(config.DCR.AllowedAudiences),
			accessHandler.HandleWithPublicAuthPathPrefixes(publicAuthPathPrefixes(config.CustomEndpoints)),
			middleware.ActivityHandler,
		))

	return server, nil
}

// ContextToIssuer is the canonical issuer source for any handler that
// builds an issuer-derived URL (OIDC discovery, RFC 8414 AS metadata,
// RFC 7591 registration_endpoint, etc.).
//
// It reads the request origin from http_utils.DomainContext(ctx), which
// is populated by zitadel's global WithOrigin middleware mounted on the
// root router at cmd/start/start.go and is therefore available on every
// request regardless of which sub-mux the handler lives behind.
//
// Important — issuer-source invariant for out-of-mux endpoints:
// Handlers that mount OUTSIDE the OIDC server's middleware chain (notably
// anything mounted via apis.RegisterHandlerOnPrefix that does not pass
// through op.NewIssuerInterceptor — for example the RFC 8414 AS metadata
// handler at /.well-known/oauth-authorization-server) MUST source the
// issuer from this function, NOT from op.IssuerFromContext.
//
// op.IssuerFromContext only sees the context value populated by
// op.NewIssuerInterceptor, which runs only inside the OIDC mux's
// middleware chain. Calling it from an out-of-mux handler returns "" and
// silently degrades every URL to a relative path. op.IssuerFromContext is
// acceptable only as a test-fixture fallback (paired with
// op.ContextWithIssuer in tests).
//
// See CONTRIBUTING.md "DCR & well-known endpoint invariants" and
// context/kits/cavekit-dcr-bootstrap-validation.md R3.
func ContextToIssuer(ctx context.Context) string {
	return http_utils.DomainContext(ctx).Origin()
}

func IssuerFromContext(_ bool) (op.IssuerFromRequest, error) {
	return func(r *http.Request) string {
		return ContextToIssuer(r.Context())
	}, nil
}

func publicAuthPathPrefixes(endpoints *EndpointConfig) []string {
	authURL := op.DefaultEndpoints.Authorization.Relative()
	keysURL := op.DefaultEndpoints.JwksURI.Relative()
	if endpoints == nil {
		return []string{oidc.DiscoveryEndpoint, authURL, keysURL}
	}
	if endpoints.Auth != nil && endpoints.Auth.Path != "" {
		authURL = endpoints.Auth.Path
	}
	if endpoints.Keys != nil && endpoints.Keys.Path != "" {
		keysURL = endpoints.Keys.Path
	}
	return []string{oidc.DiscoveryEndpoint, authURL, keysURL}
}

func createOPConfig(config Config, defaultLogoutRedirectURI string, cryptoKey []byte) (*op.Config, error) {
	opConfig := &op.Config{
		DefaultLogoutRedirectURI: defaultLogoutRedirectURI,
		CodeMethodS256:           config.CodeMethodS256,
		AuthMethodPost:           config.AuthMethodPost,
		AuthMethodPrivateKeyJWT:  config.AuthMethodPrivateKeyJWT,
		GrantTypeRefreshToken:    config.GrantTypeRefreshToken,
		RequestObjectSupported:   config.RequestObjectSupported,
		DeviceAuthorization:      config.DeviceAuth.toOPConfig(),
	}
	if cryptoLength := len(cryptoKey); cryptoLength != 32 {
		return nil, zerrors.ThrowInternalf(nil, "OIDC-D43gf", "crypto key must be 32 bytes, but is %d", cryptoLength)
	}
	copy(opConfig.CryptoKey[:], cryptoKey)
	return opConfig, nil
}

func newStorage(
	config Config,
	command *command.Commands,
	query *query.Queries,
	repo repository.Repository,
	authAlg crypto.AuthAlgorithm,
	es *eventstore.Eventstore,
	contextToIssuer func(context.Context) string,
	federateLogoutCache cache.Cache[federatedlogout.Index, string, *federatedlogout.FederatedLogout],
) *OPStorage {
	return &OPStorage{
		repo:                              repo,
		command:                           command,
		query:                             query,
		eventstore:                        es,
		defaultLoginURL:                   fmt.Sprintf("%s%s?%s=", login.HandlerPrefix, login.EndpointLogin, login.QueryAuthRequestID),
		defaultLoginURLV2:                 config.DefaultLoginURLV2,
		defaultLogoutURLV2:                config.DefaultLogoutURLV2,
		defaultAccessTokenLifetime:        config.DefaultAccessTokenLifetime,
		defaultIdTokenLifetime:            config.DefaultIdTokenLifetime,
		defaultRefreshTokenIdleExpiration: config.DefaultRefreshTokenIdleExpiration,
		defaultRefreshTokenExpiration:     config.DefaultRefreshTokenExpiration,
		authAlg:                           authAlg,
		assetAPIPrefix:                    assets.AssetAPI(),
		contextToIssuer:                   contextToIssuer,
		federateLogoutCache:               federateLogoutCache,
	}
}

func (o *OPStorage) Health(ctx context.Context) error {
	return o.repo.Health(ctx)
}
