package oidc

// inline_jwks_keyset.go bridges the inline JWK Set bytes stored on
// apps7_oidc_configs.jwks_inline (cavekit-inline-jwks.md R3) to the
// op.KeySet interface the JWTProfileVerifier expects. Used by
// `private_key_jwt` token-endpoint client authentication
// (cavekit-inline-jwks.md R6 / T-032).
//
// Implementation details:
//   - exact-`kid` match is the resolution strategy; missing kid → same
//     "invalid_client" envelope today's keySetMap path returns (the
//     verifier surfaces ErrSignatureInvalid which becomes
//     oidc.ErrInvalidClient at the call site).
//   - public-key type whitelist (RSA / EC / Ed25519). A misconfigured
//     row carrying a private-material JWK (which T-007 should have
//     refused at register-time) fails fast here rather than silently
//     signing-and-verifying.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel/internal/zerrors"
)

// inlineJWKSKeySet is the per-request KeySet that wraps a parsed
// JSONWebKeySet for op.JWTProfileVerifier consumption. Constructed
// fresh per verification — JOSE library accepts unparsed bytes via
// jose.ParseSigned, so a small struct here is the cheapest path to
// keep the existing interface.
type inlineJWKSKeySet struct {
	set jose.JSONWebKeySet
}

func newInlineJWKSKeySet(raw []byte) (*inlineJWKSKeySet, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty inline JWK Set")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("decode inline JWK Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("inline JWK Set has no keys")
	}
	return &inlineJWKSKeySet{set: set}, nil
}

// VerifySignature implements op.KeySet. Resolves the JWS header kid
// against the parsed set; on mismatch returns the same Errors.Token.Invalid
// envelope keySetMap returns so the caller (verifyClientAssertion)
// translates it to oidc.ErrInvalidClient.
func (k *inlineJWKSKeySet) VerifySignature(_ context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	if len(jws.Signatures) != 1 {
		return nil, zerrors.ThrowInvalidArgument(nil, "OIDC-Jw0V1", "Errors.Token.Invalid")
	}
	keyID := jws.Signatures[0].Header.KeyID
	for i := range k.set.Keys {
		if k.set.Keys[i].KeyID != keyID {
			continue
		}
		// Verify produces the payload bytes if the signature is valid.
		// The op.KeySet contract is: nil error + payload on success;
		// non-nil error on any failure.
		return jws.Verify(k.set.Keys[i].Key)
	}
	return nil, zerrors.ThrowInvalidArgument(nil, "OIDC-Jw0V2", "Errors.Token.Invalid")
}

// Compile-time assertion that we satisfy op.KeySet.
var _ oidc.KeySet = (*inlineJWKSKeySet)(nil)
