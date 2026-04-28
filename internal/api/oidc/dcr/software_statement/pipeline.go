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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/zitadel/zitadel/internal/telemetry/tracing"
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

	// VerificationRecorder is the per-Run metric callback (T-042).
	// Production wires this to dcr.RecordSoftwareStatementVerification.
	// nil disables emission (tests typically pass nil).
	VerificationRecorder VerificationRecorder
}

// VerificationRecorder is invoked exactly once per Run with the issuer
// (verbatim from the JWT body) and the kit-mandated result label
// (cavekit-software-statement.md R11). Empty issuer means the JWT
// failed to parse before the issuer field was populated — production
// metric closure should still record under empty `iss` so missing-iss
// rejections are observable.
type VerificationRecorder func(ctx context.Context, iss, result string)

// VerifyResult enumerates the kit-mandated label values for the
// `result` dimension on `zitadel.dcr.software_statement_verifications_total`
// (T-042) and the `result` attribute on `oidc.dcr.software_statement.verify`
// (T-041). Constants live here (alongside the producer) instead of in
// the metrics package so callers can wire either / both.
const (
	VerifyResultAccepted             = "accepted"
	VerifyResultUntrusted            = "untrusted"
	VerifyResultExpired              = "expired"
	VerifyResultReplay               = "replay"
	VerifyResultInvalidSignature     = "invalid_signature"
	VerifyResultInvalidStructure     = "invalid_structure"
	VerifyResultFetchFailed          = "fetch_failed"
	VerifyResultUnsupportedAlgorithm = "unsupported_algorithm"
	VerifyResultMissingRequiredClaim = "missing_required_claim"
	VerifyResultNotYetValid          = "not_yet_valid"
)

// resultFromParseError maps the i18n key on a ParseError to the
// kit-mandated R11 label value. Unknown keys collapse to
// `invalid_structure` — the parser's catch-all key.
func resultFromParseError(pe *ParseError) string {
	if pe == nil {
		return VerifyResultAccepted
	}
	switch pe.I18nKey {
	case InvalidStructureKey:
		return VerifyResultInvalidStructure
	case UntrustedIssuerKey:
		return VerifyResultUntrusted
	case JWKSFetchFailedKey:
		return VerifyResultFetchFailed
	case InvalidSignatureKey:
		return VerifyResultInvalidSignature
	case UnsupportedAlgorithmKey:
		return VerifyResultUnsupportedAlgorithm
	case ExpiredKey:
		return VerifyResultExpired
	case NotYetValidKey:
		return VerifyResultNotYetValid
	case ReplayKey:
		return VerifyResultReplay
	case MissingRequiredClaimKey:
		return VerifyResultMissingRequiredClaim
	default:
		return VerifyResultInvalidStructure
	}
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
	// T-041 — span name asserted verbatim by cavekit-software-statement.md
	// R11. Attributes are added once we know the iss + result; never
	// the raw JWT, raw timestamps, or JWKS payload.
	ctx, span := tracing.NewNamedSpan(ctx, "oidc.dcr.software_statement.verify")
	otelSpan := trace.SpanFromContext(ctx)
	var (
		issForSpan    string
		resultForSpan = VerifyResultAccepted
		runErr        *ParseError
	)
	defer func() {
		// Outer defer: emit attributes + metric using the final result
		// captured by the inner defer below. iss attribute carries the
		// JWT body issuer verbatim — RFC 7519 §4.1.1 identifier-only,
		// non-secret. result attribute is the kit-mandated R11 enum.
		// When resultForSpan == "" the verifier skipped (parsed==nil
		// after trim) — emit neither attributes nor metric so callers
		// see a clean "no software_statement" trace.
		if resultForSpan != "" {
			otelSpan.SetAttributes(
				attribute.String("iss", issForSpan),
				attribute.String("result", resultForSpan),
			)
			if deps.VerificationRecorder != nil {
				deps.VerificationRecorder(ctx, issForSpan, resultForSpan)
			}
		}
		span.End()
	}()
	defer func() {
		if runErr != nil {
			resultForSpan = resultFromParseError(runErr)
		}
	}()
	now := time.Now
	if deps.Now != nil {
		now = deps.Now
	}

	parsed, err := Parse(rawJWT)
	if err != nil {
		if pe, ok := err.(*ParseError); ok {
			runErr = pe
			return nil, pe
		}
		runErr = &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: parser returned a non-ParseError",
			I18nKey:     InvalidStructureKey,
			Wrapped:     err,
		}
		return nil, runErr
	}
	if parsed == nil {
		// rawJWT was empty after trim — short-circuit no-op. Reset the
		// outer defer to skip attribute / metric emission since the
		// caller's happy path also skipped this branch.
		resultForSpan = ""
		return nil, nil
	}
	issForSpan = parsed.Issuer

	descriptor, lookupErr := Lookup(parsed.Issuer, deps.TrustedIssuers)
	if lookupErr != nil {
		runErr = lookupErr
		return nil, lookupErr
	}

	jwksBytes, fetchErr := deps.JWKSCache.Get(ctx, *descriptor)
	if fetchErr != nil {
		runErr = fetchErr
		return nil, fetchErr
	}

	if vErr := Verify(parsed, deps.AllowedAlgorithms, jwksBytes, now()); vErr != nil {
		runErr = vErr
		return nil, vErr
	}

	if rcErr := VerifyRequiredClaims(parsed, descriptor.RequiredClaims); rcErr != nil {
		runErr = rcErr
		return nil, rcErr
	}

	if rrErr := RecordReplay(ctx, parsed, deps.ReplayRecorder, now(), deps.JTIRetentionBuffer); rrErr != nil {
		runErr = rrErr
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
