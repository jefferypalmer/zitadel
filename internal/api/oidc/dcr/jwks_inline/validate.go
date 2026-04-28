// Package jwks_inline implements cavekit-inline-jwks.md R2 — per-JWK
// validation of the `jwks` member of an RFC 7591 client-metadata body.
// The container-level decode and mutual-exclusion check live in
// internal/api/oidc/dcr/jwks_inline_validate.go (T-006); this package
// owns the JWK-by-JWK rules.
//
// Errors returned here are *ValidateError (compatible with the rest of
// the DCR error envelope flow). All error keys live under
// `Errors.DCR.Jwks.*` so a single i18n test can pin them.
package jwks_inline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// MaxKeys is the cap from cavekit-inline-jwks.md R2: 10 keys per JWK
// Set. The 11th key is rejected with `TooManyKeys`.
const MaxKeys = 10

// MaxSerializedBytes caps the *normalized* (sorted-key) re-serialization
// of the JWK Set. R2 specifies 16 KiB.
const MaxSerializedBytes = 16 * 1024

// AllowedAlgorithms enumerates the JOSE `alg` values cavekit-inline-jwks.md
// R2 accepts when a JWK declares one. Absence of `alg` is permitted.
var AllowedAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
	"EdDSA": {},
}

// PrivateMembers lists the JWK fields that, if present on any key,
// trigger the `PrivateKeyMaterial` rejection. Any one is enough — clients
// MUST NOT register private material under inline `jwks`.
var PrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi"}

// Error keys (cavekit-inline-jwks.md R2). Kept as exported constants so
// the i18n test can assert all-22-locales coverage in one place.
const (
	KeyMutuallyExclusive   = "Errors.DCR.Jwks.MutuallyExclusive"
	KeyInvalidStructure    = "Errors.DCR.Jwks.InvalidStructure"
	KeyDuplicateKid        = "Errors.DCR.Jwks.DuplicateKid"
	KeyUnsupportedAlgorithm = "Errors.DCR.Jwks.UnsupportedAlgorithm"
	KeyPrivateKeyMaterial  = "Errors.DCR.Jwks.PrivateKeyMaterial"
	KeyTooManyKeys         = "Errors.DCR.Jwks.TooManyKeys"
	KeyTooLarge            = "Errors.DCR.Jwks.TooLarge"
	KeyEmptyKeySet         = "Errors.DCR.Jwks.EmptyKeySet"
)

// ValidateError carries the RFC 7591 §3.2.2 envelope code, the human
// description, and the i18n key. The DCR register handler converts this
// to its own ClampError-style envelope at the call site.
type ValidateError struct {
	Code        string
	Description string
	I18nKey     string
}

func (e *ValidateError) Error() string { return e.Code + ": " + e.Description }

func newErr(code, key, desc string) *ValidateError {
	return &ValidateError{Code: code, Description: desc, I18nKey: key}
}

// Validate runs cavekit-inline-jwks.md R2 over a `jwks` JSON value (the
// raw RFC7591Metadata.Jwks field). The caller is expected to have run
// the R1 mutual-exclusion / object-with-keys-array check first; we
// re-check the structural shape here as defense-in-depth so this
// function is safe to call independently from a test.
//
// On success returns the parsed JWK Set bytes (re-encoded with sorted
// keys, used by callers as the canonical storage form per
// cavekit-inline-jwks.md R5 byte-equality contract). On failure returns
// nil + a *ValidateError.
//
// `use=enc` JWKs are silently dropped (R2 carve-out); the returned set
// only contains `use=sig` (or absent-`use`) keys. The MaxKeys / MaxSize
// caps apply to the input as received, not the post-drop set, so a
// caller cannot push 20 enc-keys to amortise a tiny sig-key over the
// per-key cost.
func Validate(raw json.RawMessage) ([]byte, *ValidateError) {
	if len(raw) == 0 {
		return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
			"jwks: must be a JSON object containing a `keys` array")
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
			"jwks: must be a JSON object")
	}
	keysRaw, ok := top["keys"]
	if !ok {
		return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
			"jwks: object must contain a `keys` array")
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(keysRaw, &keys); err != nil {
		return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
			"jwks: `keys` must be a JSON array")
	}
	if len(keys) == 0 {
		return nil, newErr("invalid_client_metadata", KeyEmptyKeySet,
			"jwks: `keys` must contain at least one JWK")
	}
	if len(keys) > MaxKeys {
		return nil, newErr("invalid_client_metadata", KeyTooManyKeys,
			fmt.Sprintf("jwks: at most %d keys are accepted (got %d)", MaxKeys, len(keys)))
	}

	seenKid := make(map[string]struct{}, len(keys))
	kept := make([]json.RawMessage, 0, len(keys))

	for i, kraw := range keys {
		var jwk map[string]json.RawMessage
		if err := json.Unmarshal(kraw, &jwk); err != nil {
			return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
				fmt.Sprintf("jwks.keys[%d]: must be a JSON object", i))
		}

		// `use` filter — dropped silently when "enc".
		if useRaw, ok := jwk["use"]; ok {
			var use string
			if err := json.Unmarshal(useRaw, &use); err != nil {
				return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
					fmt.Sprintf("jwks.keys[%d]: `use` must be a string", i))
			}
			if use == "enc" {
				continue
			}
			if use != "" && use != "sig" {
				return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
					fmt.Sprintf("jwks.keys[%d]: `use`=%q not supported", i, use))
			}
		}

		// `kid` required + non-empty.
		var kid string
		if kidRaw, ok := jwk["kid"]; ok {
			_ = json.Unmarshal(kidRaw, &kid)
		}
		if strings.TrimSpace(kid) == "" {
			return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
				fmt.Sprintf("jwks.keys[%d]: `kid` is required", i))
		}
		if _, dup := seenKid[kid]; dup {
			return nil, newErr("invalid_client_metadata", KeyDuplicateKid,
				fmt.Sprintf("jwks.keys[%d]: duplicate `kid`", i))
		}
		seenKid[kid] = struct{}{}

		// `kty` ∈ {RSA, EC, OKP}.
		var kty string
		if ktyRaw, ok := jwk["kty"]; ok {
			_ = json.Unmarshal(ktyRaw, &kty)
		}
		switch kty {
		case "RSA", "EC", "OKP":
		default:
			return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
				fmt.Sprintf("jwks.keys[%d]: `kty`=%q must be one of RSA/EC/OKP", i, kty))
		}

		// `alg` if present must be in AllowedAlgorithms.
		if algRaw, ok := jwk["alg"]; ok {
			var alg string
			if err := json.Unmarshal(algRaw, &alg); err != nil {
				return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
					fmt.Sprintf("jwks.keys[%d]: `alg` must be a string", i))
			}
			if alg != "" {
				if _, ok := AllowedAlgorithms[alg]; !ok {
					return nil, newErr("invalid_client_metadata", KeyUnsupportedAlgorithm,
						fmt.Sprintf("jwks.keys[%d]: `alg`=%q is not supported", i, alg))
				}
			}
		}

		// Reject any private-material field — independent check per
		// cavekit-inline-jwks.md R2 ("each field independent").
		for _, p := range PrivateMembers {
			if _, present := jwk[p]; present {
				return nil, newErr("invalid_client_metadata", KeyPrivateKeyMaterial,
					fmt.Sprintf("jwks.keys[%d]: private-material field `%s` not permitted", i, p))
			}
		}

		// Rebuild the kept JWK with sorted member keys so the canonical
		// form is byte-stable (cavekit-inline-jwks.md R5).
		canonical, err := canonicaliseKey(jwk)
		if err != nil {
			return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
				fmt.Sprintf("jwks.keys[%d]: cannot serialise", i))
		}
		kept = append(kept, canonical)
	}

	if len(kept) == 0 {
		// All keys had `use=enc`. Equivalent to an empty key set as
		// far as DCR registration is concerned.
		return nil, newErr("invalid_client_metadata", KeyEmptyKeySet,
			"jwks: `keys` must contain at least one signing JWK")
	}

	out, err := canonicaliseSet(kept)
	if err != nil {
		return nil, newErr("invalid_client_metadata", KeyInvalidStructure,
			"jwks: cannot serialise canonical form")
	}
	if len(out) > MaxSerializedBytes {
		return nil, newErr("invalid_client_metadata", KeyTooLarge,
			fmt.Sprintf("jwks: serialised size %d exceeds %d-byte cap", len(out), MaxSerializedBytes))
	}
	return out, nil
}

// canonicaliseKey re-encodes a JWK with member keys in lexicographic
// order. Allows the storage layer (T-015) to compare bytes between
// PUT request and GET response without re-decoding.
func canonicaliseKey(jwk map[string]json.RawMessage) ([]byte, error) {
	keys := make([]string, 0, len(jwk))
	for k := range jwk {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		ek, _ := json.Marshal(k)
		b.Write(ek)
		b.WriteByte(':')
		b.Write(jwk[k])
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

func canonicaliseSet(keys []json.RawMessage) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`{"keys":[`)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(k)
	}
	b.WriteString(`]}`)
	return []byte(b.String()), nil
}

// Fingerprint returns a stable SHA-256 hex of the canonical bytes for
// log/metric correlation (NOT for cryptographic identity). Helpful for
// audit trails — the `dcr.jwks.source=inline` span attribute (T-044)
// can pair with this fingerprint without ever logging the JWK Set.
func Fingerprint(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum)
}
