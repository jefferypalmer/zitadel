package start

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zitadel/logging"

	http_util "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/api/oidc"
	"github.com/zitadel/zitadel/internal/api/oidc/dcr"
	"github.com/zitadel/zitadel/internal/api/oidc/dcr/software_statement"
	"github.com/zitadel/zitadel/internal/query"
)

// buildSoftwareStatementPipeline assembles *software_statement.PipelineDeps
// for production. cavekit-software-statement.md R14 (T-023): without this
// wiring, the entire R5/R9/R13 verifier surface is dead in production —
// dcr/wire.go short-circuits to the Phase-1 fallback when SoftwareStatementPipeline
// is nil.
//
// TokenEndpoint is sourced from the externally-resolvable issuer URL plus
// the standard /oauth/v2/token suffix (matches internal/api/oidc/server.go's
// op.NewEndpoint("/oauth/v2/token") registration).
func buildSoftwareStatementPipeline(config *Config, queries *query.Queries) (*software_statement.PipelineDeps, error) {
	if !config.OIDC.DCR.SoftwareStatement.Enabled {
		return nil, errors.New("buildSoftwareStatementPipeline called with SoftwareStatement.Enabled=false")
	}

	fetcher, err := dcr.NewJwksFetcher(dcr.JwksFetcherConfig{
		HTTPTimeout:        config.OIDC.DCR.JwksURI.HTTPTimeout,
		AllowLoopbackInDev: config.OIDC.DCR.JwksURI.AllowLoopbackInDev,
		DisallowedIPRanges: config.OIDC.DCR.JwksURI.DisallowedIPRanges,
	})
	if err != nil {
		return nil, fmt.Errorf("jwks fetcher: %w", err)
	}

	cache := software_statement.NewJWKSCache(fetcher, config.OIDC.DCR.SoftwareStatement.JWKSCacheTTL)
	cache.SetLookupRecorder(func(ctx context.Context, iss string, outcome software_statement.CacheLookupOutcome) {
		dcr.RecordSoftwareStatementJWKSCacheLookup(ctx, iss, string(outcome))
	})

	trustedIssuers := convertTrustedIssuers(config.OIDC.DCR.SoftwareStatement.TrustedIssuers)
	// Codex F-102 / P2 — empty TrustedIssuers when SoftwareStatement.Enabled
	// is by-design Phase-1 backwards-compat (the lookup.go R3 contract:
	// any non-empty `iss` is rejected as `unapproved_software_statement`).
	// But it's a foot-gun: an operator who turned on Enabled expecting
	// software_statement registrations to start succeeding gets the same
	// rejection as Enabled=false. Emit a startup WARN so misconfig is
	// surfaced in logs rather than only at request time.
	if len(trustedIssuers) == 0 {
		logging.Warn("dcr: OIDC.DCR.SoftwareStatement.Enabled=true but TrustedIssuers is empty — every software_statement will be rejected as unapproved_software_statement (Phase-1 backwards-compat). Configure at least one TrustedIssuer to actually verify statements.")
	}

	tokenEndpoint := http_util.BuildHTTP(config.ExternalDomain, config.ExternalPort, config.ExternalSecure) + "/oauth/v2/token"

	deps := &software_statement.PipelineDeps{
		TrustedIssuers:       trustedIssuers,
		AllowedAlgorithms:    config.OIDC.DCR.SoftwareStatement.AllowedAlgorithms,
		JWKSCache:            cache,
		ReplayRecorder:       newJTIRecorder(queries),
		JTIRetentionBuffer:   config.OIDC.DCR.SoftwareStatement.JTIRetentionBuffer,
		Now:                  time.Now,
		VerificationRecorder: software_statement.VerificationRecorder(dcr.RecordSoftwareStatementVerification),
		TokenEndpoint:        tokenEndpoint,
		SkipAudValidation:    config.OIDC.DCR.SoftwareStatement.SkipAudValidation,
	}

	if err := deps.Validate(); err != nil {
		return nil, err
	}
	return deps, nil
}

// convertTrustedIssuers translates the oidc.DCRTrustedIssuer config shape
// to the software_statement-internal mirror so the dcr verifier package
// stays independent of the oidc config types.
func convertTrustedIssuers(cfg []oidc.DCRTrustedIssuer) []software_statement.TrustedIssuer {
	if len(cfg) == 0 {
		return nil
	}
	out := make([]software_statement.TrustedIssuer, len(cfg))
	for i, e := range cfg {
		out[i] = software_statement.TrustedIssuer{
			Issuer:         e.Issuer,
			JWKSURI:        e.JWKSURI,
			RequiredClaims: e.RequiredClaims,
		}
	}
	return out
}

// newJTIRecorder bridges software_statement.JTIRecorder to query.RecordSoftwareStatementJTI,
// mapping the int-typed result enums between the two packages.
func newJTIRecorder(queries *query.Queries) software_statement.JTIRecorder {
	return func(ctx context.Context, iss, jti string, createdAt, expiresAt time.Time) (software_statement.JTIRecorderResult, error) {
		got, err := queries.RecordSoftwareStatementJTI(ctx, iss, jti, createdAt, expiresAt)
		if err != nil {
			return 0, err
		}
		switch got {
		case query.JTIInserted:
			return software_statement.JTIRecorderInserted, nil
		case query.JTIAlreadySeen:
			return software_statement.JTIRecorderAlreadySeen, nil
		default:
			return 0, fmt.Errorf("software_statement: unknown JTI recorder result %d", got)
		}
	}
}
