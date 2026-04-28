package software_statement

// lookup.go implements cavekit-software-statement.md R3 — trusted-issuer
// lookup. Case-sensitive exact-string match against configured
// `OIDC.DCR.SoftwareStatement.TrustedIssuers`; mismatch returns the
// `unapproved_software_statement` envelope (RFC 7591 §3.2.2) keyed
// `Errors.DCR.SoftwareStatement.UntrustedIssuer`. The `error_description`
// MUST NOT echo the offending `iss` (R3) — operator-controlled trusted
// issuer names ARE safe to log, but reflecting an attacker-controlled
// `iss` lets a verifier serve as an arbitrary string-mirror.

// UntrustedIssuerKey is the i18n key returned for any R3 mismatch.
const UntrustedIssuerKey = "Errors.DCR.SoftwareStatement.UntrustedIssuer"

// TrustedIssuer is the lookup-side view of a configured trusted-issuer
// entry. Mirrors `oidc.DCRTrustedIssuer` but lives here so the dcr
// package can import this lookup without pulling in the wider oidc
// config types.
type TrustedIssuer struct {
	Issuer         string
	JWKSURI        string
	RequiredClaims []string
}

// Lookup returns the configured trusted-issuer descriptor whose
// `Issuer` matches the JWT body `iss` byte-for-byte. On miss returns
// nil + a *ParseError keyed UntrustedIssuerKey with envelope code
// `unapproved_software_statement`. The error description names the
// rejection reason, NOT the offending iss (per R3).
//
// `iss` is taken from a previously-Parsed JWT (the body claim, not the
// header). An empty `iss` is rejected by the parser already; this
// function still defends against the empty case to keep the contract
// total.
//
// Empty `trustedIssuers` (operator hasn't configured any) preserves
// the Phase 1 envelope by returning nil + UntrustedIssuer for any
// non-empty `iss` (R1: "Empty TrustedIssuers preserves Phase 1
// `unapproved_software_statement`").
func Lookup(iss string, trustedIssuers []TrustedIssuer) (*TrustedIssuer, *ParseError) {
	if iss == "" {
		return nil, &ParseError{
			Code:        "unapproved_software_statement",
			Description: "software_statement: issuer is required",
			I18nKey:     UntrustedIssuerKey,
		}
	}
	for i := range trustedIssuers {
		if trustedIssuers[i].Issuer == iss {
			// Return a defensive copy so callers cannot mutate the
			// configured RequiredClaims slice.
			out := trustedIssuers[i]
			if len(out.RequiredClaims) > 0 {
				out.RequiredClaims = append([]string(nil), trustedIssuers[i].RequiredClaims...)
			}
			return &out, nil
		}
	}
	return nil, &ParseError{
		Code:        "unapproved_software_statement",
		Description: "software_statement: issuer is not trusted",
		I18nKey:     UntrustedIssuerKey,
	}
}
