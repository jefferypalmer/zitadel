package software_statement

// pipeline.go is the integration entry-point used by the register
// handler (T-031). It composes parse → lookup → fetch → verify →
// required-claims → replay-record → override-mapping into a single
// `Run` call so the handler stays linear.
//
// Failure routing matches cavekit-software-statement.md R8:
//   - R2 / R3 / R5 / R7 rejection → ParseError; handler writes the
//     RFC 7591 envelope and pushes NO registration event.
//   - R9 replay rejection → ParseError keyed Replay; same envelope
//     contract; the R11 metric site (T-042) surfaces this branch via
//     `result=replay` distinct from `result=accepted`.
//   - Success → caller proceeds to ValidateAndClampMetadata's second
//     pass (over the override-merged metadata) and then to deps.Register.

import (
	"context"
	"encoding/json"
	"time"
)

// PipelineDeps carries everything Run needs. Constructed once at
// startup and reused per request — tests can pass a stub fetcher /
// recorder / clock so no network or DB is required.
type PipelineDeps struct {
	// TrustedIssuers is the operator-configured allow-list. Empty list
	// means any non-empty `software_statement` is rejected with the
	// `unapproved_software_statement` envelope (cavekit-software-
	// statement.md R3 + the Phase 1 envelope-preservation contract).
	TrustedIssuers []TrustedIssuer

	// AllowedAlgorithms is `OIDC.DCR.SoftwareStatement.AllowedAlgorithms`.
	// `none` and `HS*` are also runtime-refused even if listed.
	AllowedAlgorithms []string

	// JWKSCache fetches per-issuer JWKS. cavekit-software-statement.md
	// R4 — TTL'd, refetch failure does NOT serve stale.
	JWKSCache *JWKSCache

	// ReplayRecorder writes the (iss, jti, expires_at) row. Production
	// closure calls Queries.RecordSoftwareStatementJTI; T-014 owns the
	// SQL.
	ReplayRecorder JTIRecorder

	// JTIRetentionBuffer is the time after `parsed.Body.Exp` we keep
	// the dedupe row before the janitor reaps it. Default 24h —
	// `OIDC.DCR.SoftwareStatement.JTIRetentionBuffer`.
	JTIRetentionBuffer time.Duration

	// Now is the clock seam. Production wires `time.Now`; tests pin a
	// fixed value to avoid time.Sleep in the iat / exp / replay-
	// retention math.
	Now func() time.Time
}

// Result returns from a successful Run. JTI is the verified JWT's
// `jti` claim — the register handler stores it on
// ApplicationDynamicallyRegisteredEvent.SoftwareStatementJTI per
// cavekit-software-statement.md R8. MergedExtra is the JWT-derived
// override map ready for application onto a request-body map (use
// MergedMetadata to splice).
type Result struct {
	JTI         string
	Issuer      string
	MergedExtra map[string]json.RawMessage
}

// Run executes the full pipeline against a `software_statement` JWT.
// `rawJWT` empty short-circuits: returns nil + nil so the caller's
// happy path simply skips this branch (no event implication, no
// metric implication).
//
// On any failure returns nil + a *ParseError. Caller maps the i18n key
// to the localised error_description and writes the RFC 7591 §3.2.2
// envelope. The handler MUST NOT push any registration event when
// Run returned a non-nil error.
func Run(ctx context.Context, rawJWT string, deps PipelineDeps) (*Result, *ParseError) {
	if rawJWT == "" {
		return nil, nil
	}
	now := time.Now
	if deps.Now != nil {
		now = deps.Now
	}

	parsed, err := Parse(rawJWT)
	if err != nil {
		if pe, ok := err.(*ParseError); ok {
			return nil, pe
		}
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: parser returned a non-ParseError",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
	}
	if parsed == nil {
		// rawJWT was empty after trim — short-circuit no-op.
		return nil, nil
	}

	descriptor, lookupErr := Lookup(parsed.Issuer, deps.TrustedIssuers)
	if lookupErr != nil {
		return nil, lookupErr
	}

	jwksBytes, fetchErr := deps.JWKSCache.Get(ctx, *descriptor)
	if fetchErr != nil {
		return nil, fetchErr
	}

	if vErr := Verify(parsed, deps.AllowedAlgorithms, jwksBytes, now()); vErr != nil {
		return nil, vErr
	}

	if rcErr := VerifyRequiredClaims(parsed, descriptor.RequiredClaims); rcErr != nil {
		return nil, rcErr
	}

	if rrErr := RecordReplay(ctx, parsed, deps.ReplayRecorder, now(), deps.JTIRetentionBuffer); rrErr != nil {
		return nil, rrErr
	}

	merged := make(map[string]json.RawMessage, len(mappedClaims))
	for _, claim := range mappedClaims {
		if v, ok := parsed.Body.Extra[claim]; ok && len(v) > 0 {
			merged[claim] = v
		}
	}

	return &Result{
		JTI:         parsed.Body.Jti,
		Issuer:      parsed.Issuer,
		MergedExtra: merged,
	}, nil
}
