package software_statement

// verify.go implements cavekit-software-statement.md R5 — signature +
// standard JWT claim verification. Runs AFTER R2 structural parse
// (parse.go) and R3 trusted-issuer lookup (lookup.go) succeed; receives
// the descriptor's JWKS bytes from the per-issuer cache (T-020).
//
// Rejection keys (kit R5):
//   - InvalidSignature        — kid mismatch / Verify failed
//   - UnsupportedAlgorithm    — alg not in AllowedAlgorithms
//   - Expired                 — exp < now (no skew)
//   - NotYetValid             — nbf > now
//   - Replay                  — JTI seen before (handled outside; verifier
//                               surfaces the key constant for the caller)
//   - InvalidStructure        — missing exp / iat / jti, iat too far in
//                               future
//
// `none` and `HS*` algorithms are rejected at runtime even if the
// configured `AllowedAlgorithms` would tolerate them — defense-in-depth
// per kit R5 ("none/HS* always rejected").

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// IatMaxFuture caps how far into the future a JWT's `iat` claim may be
// (clock-skew tolerance). cavekit-software-statement.md R5: `iat ≤ now+5m`.
const IatMaxFuture = 5 * time.Minute

// SkewToleranceForExp is the kit's explicit zero — exp >= now with no
// skew tolerance per R5 ("exp ≥ now (no skew)"). Constant for clarity.
const SkewToleranceForExp = 0 * time.Second

// Error keys for R5 verification failures. Replay key lives here too so
// the JTI dedupe call site (T-030) emits the same envelope without
// reaching across packages. InvalidAudienceKey is R13 (T-006).
const (
	InvalidSignatureKey     = "Errors.DCR.SoftwareStatement.InvalidSignature"
	UnsupportedAlgorithmKey = "Errors.DCR.SoftwareStatement.UnsupportedAlgorithm"
	ExpiredKey              = "Errors.DCR.SoftwareStatement.Expired"
	NotYetValidKey          = "Errors.DCR.SoftwareStatement.NotYetValid"
	ReplayKey               = "Errors.DCR.SoftwareStatement.Replay"
	InvalidAudienceKey      = "Errors.DCR.SoftwareStatement.InvalidAudience"
)

// Verify runs cavekit-software-statement.md R5 against a previously-
// parsed software_statement (from parse.go) using:
//
//   - allowedAlgorithms: the operator-configured allow-list from
//     `OIDC.DCR.SoftwareStatement.AllowedAlgorithms`. `none` and any
//     `HS*` entry the operator left in is refused at runtime regardless.
//   - jwksBytes: JWKS JSON returned by the per-issuer cache (T-020).
//   - now: the current time. Threaded as an argument so tests don't
//     have to time.Sleep through the iat/exp checks.
//
// Returns nil + nil on a fully-valid software_statement. On failure
// returns nil + a *ParseError keyed to the matching R5 i18n key. The
// envelope code is `invalid_software_statement` per RFC 7591 §3.2.2 in
// every failure case (no `unapproved_software_statement` here — that
// code is owned by the trusted-issuer lookup in R3).
func Verify(
	parsed *Parsed,
	allowedAlgorithms []string,
	jwksBytes []byte,
	now time.Time,
) *ParseError {
	if parsed == nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: parser returned nil",
			I18nKey:     InvalidSignatureKey,
		}
	}

	// Header `alg`. Reject none/HS* at runtime regardless of config.
	alg := strings.TrimSpace(parsed.Header.Alg)
	if alg == "" || alg == "none" || strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: alg `none` or HS* symmetric variants are forbidden",
			I18nKey:     UnsupportedAlgorithmKey,
		}
	}
	if !contains(allowedAlgorithms, alg) {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: alg not in AllowedAlgorithms",
			I18nKey:     UnsupportedAlgorithmKey,
		}
	}

	// Standard claims structural presence. exp/iat/jti REQUIRED; nbf
	// optional but if present must be ≤ now.
	if parsed.Body.Exp == nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: claim `exp` is required",
			I18nKey:     InvalidStructureKey,
		}
	}
	if parsed.Body.Iat == nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: claim `iat` is required",
			I18nKey:     InvalidStructureKey,
		}
	}
	if strings.TrimSpace(parsed.Body.Jti) == "" {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: claim `jti` is required",
			I18nKey:     InvalidStructureKey,
		}
	}

	exp := time.Unix(*parsed.Body.Exp, 0)
	iat := time.Unix(*parsed.Body.Iat, 0)
	if exp.Before(now) {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: token is expired",
			I18nKey:     ExpiredKey,
		}
	}
	if iat.After(now.Add(IatMaxFuture)) {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: fmt.Sprintf("software_statement: claim `iat` more than %s in the future", IatMaxFuture),
			I18nKey:     InvalidStructureKey,
		}
	}
	if parsed.Body.Nbf != nil {
		nbf := time.Unix(*parsed.Body.Nbf, 0)
		if nbf.After(now) {
			return &ParseError{
				Code:        "invalid_software_statement",
				Description: "software_statement: token is not yet valid",
				I18nKey:     NotYetValidKey,
			}
		}
	}

	// Signature verification. Resolve the JWK from the issuer's JWKS
	// by exact-`kid` match (kit R5: "kid exact-string match → JWK;
	// mismatch → InvalidSignature"). The JOSE header MUST carry kid;
	// missing kid would force a probe across every key in the set,
	// which the kit refuses.
	if strings.TrimSpace(parsed.Header.Kid) == "" {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: header `kid` is required",
			I18nKey:     InvalidSignatureKey,
		}
	}
	jwk, err := selectJWKByKid(jwksBytes, parsed.Header.Kid)
	if err != nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: kid not found in issuer JWKS",
			I18nKey:     InvalidSignatureKey,
			Wrapped:     err,
		}
	}

	signature, err := jose.ParseSigned(parsed.RawJWT, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: signature parse failed",
			I18nKey:     InvalidSignatureKey,
			Wrapped:     err,
		}
	}
	if _, err := signature.Verify(jwk.Key); err != nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: signature verification failed",
			I18nKey:     InvalidSignatureKey,
			Wrapped:     err,
		}
	}

	return nil
}

// VerifyAudience implements cavekit-software-statement.md R13. When the
// JWT body carries an `aud` claim, it MUST equal (string form) or
// contain (array form) the configured token-endpoint URL. Absent `aud`
// is unchanged behavior — no failure mode added. `skipAudValidation`
// reverts to Phase 2 status quo (no aud check) and is intended only
// for operators on legacy issuers that cannot mint audience-scoped
// software statements; default false.
//
// On mismatch returns a *ParseError keyed `InvalidAudienceKey`; the
// envelope code stays `invalid_software_statement` per RFC 7591 §3.2.2.
// The pipeline maps this i18n key to the `invalid_audience` result-
// label value on `zitadel.dcr.software_statement_verifications_total`.
//
// cavekit-software-statement.md R15 (T-024): when skipAudValidation is
// false, an empty tokenEndpoint is a misconfiguration. We reject all
// `aud` values defensively rather than accepting on the empty-equals-
// empty path. PipelineDeps.Validate() should already have refused to
// boot, but defense-in-depth blocks any test seam that constructs the
// pipeline directly.
func VerifyAudience(parsed *Parsed, tokenEndpoint string, skipAudValidation bool) *ParseError {
	if skipAudValidation {
		return nil
	}
	if parsed == nil || parsed.Body.Aud == nil {
		return nil
	}
	if tokenEndpoint == "" {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: server misconfiguration — token endpoint not configured for audience validation",
			I18nKey:     InvalidAudienceKey,
		}
	}
	switch v := parsed.Body.Aud.(type) {
	case string:
		if v == tokenEndpoint {
			return nil
		}
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == tokenEndpoint {
				return nil
			}
		}
	}
	return &ParseError{
		Code:        "invalid_software_statement",
		Description: "software_statement: claim `aud` does not match the token endpoint",
		I18nKey:     InvalidAudienceKey,
	}
}

// selectJWKByKid decodes the JWKS bytes into a JSONWebKeySet and
// returns the key whose `Kid` matches exactly. Public-key forms only
// — RSA / EC / Ed25519. Private material would have been refused
// upstream by jwks_inline.Validate or by the issuer's responsibility
// to publish only public keys; this function additionally checks the
// returned key is one of the supported public-key types so a
// mistakenly-published private key does not silently sign-and-verify.
func selectJWKByKid(jwksBytes []byte, kid string) (*jose.JSONWebKey, error) {
	if len(jwksBytes) == 0 {
		return nil, errors.New("empty JWKS")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	for i := range set.Keys {
		if set.Keys[i].KeyID != kid {
			continue
		}
		if !isAcceptablePublicKey(set.Keys[i].Key) {
			return nil, errors.New("matching JWK is not a supported public-key type")
		}
		return &set.Keys[i], nil
	}
	return nil, errors.New("no JWK in set matches header kid")
}

func isAcceptablePublicKey(key any) bool {
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
