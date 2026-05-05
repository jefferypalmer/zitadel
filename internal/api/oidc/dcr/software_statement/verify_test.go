package software_statement

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// signECTestStatement returns (rawJWT, jwksBytes, kid). The signing
// key is fresh per test so no fixture coordination is needed.
func signECTestStatement(t *testing.T, kid string, claims map[string]any, alg jose.SignatureAlgorithm) (string, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	signingKey := jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: priv, KeyID: kid}}
	signer, err := jose.NewSigner(signingKey,
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	body, _ := json.Marshal(claims)
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	jwk := jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: string(alg), Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, _ := json.Marshal(jwks)
	return compact, jwksBytes
}

func TestVerify_HappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{
		"iss": "https://issuer.example",
		"jti": "j1",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
		"sub": "client-x",
	}
	raw, jwks := signECTestStatement(t, "k1", claims, jose.ES256)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e := Verify(parsed, []string{"ES256"}, jwks, now); e != nil {
		t.Fatalf("Verify: %v", e)
	}
}

func TestVerify_BadSignatureRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{
		"iss": "https://issuer.example",
		"jti": "j1",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}
	raw, _ := signECTestStatement(t, "k1", claims, jose.ES256)
	// Use a DIFFERENT key in the JWKS so signature verification fails.
	_, otherJWKS := signECTestStatement(t, "k1", claims, jose.ES256)
	parsed, _ := Parse(raw)
	err := Verify(parsed, []string{"ES256"}, otherJWKS, now)
	if err == nil || err.I18nKey != InvalidSignatureKey {
		t.Fatalf("want InvalidSignature, got %+v", err)
	}
}

func TestVerify_KidMismatchRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{"iss": "https://issuer.example", "jti": "j1", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	raw, _ := signECTestStatement(t, "k1", claims, jose.ES256)
	_, otherJWKS := signECTestStatement(t, "k-different", claims, jose.ES256)
	parsed, _ := Parse(raw)
	err := Verify(parsed, []string{"ES256"}, otherJWKS, now)
	if err == nil || err.I18nKey != InvalidSignatureKey {
		t.Fatalf("want InvalidSignature, got %+v", err)
	}
}

func TestVerify_RejectsNoneAlg(t *testing.T) {
	parsed := &Parsed{
		Header: Header{Alg: "none"},
		Body:   Body{Iss: "x", Jti: "j", Exp: ptrInt64(time.Now().Add(time.Hour).Unix()), Iat: ptrInt64(time.Now().Unix())},
	}
	err := Verify(parsed, []string{"none", "ES256"}, []byte(`{"keys":[]}`), time.Now())
	if err == nil || err.I18nKey != UnsupportedAlgorithmKey {
		t.Fatalf("want UnsupportedAlgorithm for none, got %+v", err)
	}
}

func TestVerify_RejectsHS256_DefenseInDepth(t *testing.T) {
	parsed := &Parsed{
		Header: Header{Alg: "HS256"},
		Body:   Body{Iss: "x", Jti: "j", Exp: ptrInt64(time.Now().Add(time.Hour).Unix()), Iat: ptrInt64(time.Now().Unix())},
	}
	// AllowedAlgorithms tolerates HS256 (operator misconfiguration);
	// runtime MUST reject it anyway.
	err := Verify(parsed, []string{"HS256", "ES256"}, []byte(`{"keys":[]}`), time.Now())
	if err == nil || err.I18nKey != UnsupportedAlgorithmKey {
		t.Fatalf("want UnsupportedAlgorithm for HS256, got %+v", err)
	}
}

func TestVerify_AlgNotInAllowList(t *testing.T) {
	parsed := &Parsed{
		Header: Header{Alg: "RS512"},
		Body:   Body{Iss: "x", Jti: "j", Exp: ptrInt64(time.Now().Add(time.Hour).Unix()), Iat: ptrInt64(time.Now().Unix())},
	}
	err := Verify(parsed, []string{"ES256"}, []byte(`{"keys":[]}`), time.Now())
	if err == nil || err.I18nKey != UnsupportedAlgorithmKey {
		t.Fatalf("want UnsupportedAlgorithm, got %+v", err)
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{"iss": "x", "jti": "j", "iat": now.Add(-time.Hour).Unix(), "exp": now.Add(-time.Minute).Unix()}
	raw, jwks := signECTestStatement(t, "k1", claims, jose.ES256)
	parsed, _ := Parse(raw)
	err := Verify(parsed, []string{"ES256"}, jwks, now)
	if err == nil || err.I18nKey != ExpiredKey {
		t.Fatalf("want Expired, got %+v", err)
	}
}

func TestVerify_RejectsIatTooFarInFuture(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{
		"iss": "x", "jti": "j",
		"iat": now.Add(IatMaxFuture + time.Minute).Unix(),
		"exp": now.Add(2 * time.Hour).Unix(),
	}
	raw, jwks := signECTestStatement(t, "k1", claims, jose.ES256)
	parsed, _ := Parse(raw)
	err := Verify(parsed, []string{"ES256"}, jwks, now)
	if err == nil || err.I18nKey != InvalidStructureKey {
		t.Fatalf("want InvalidStructure (iat too far), got %+v", err)
	}
}

func TestVerify_NbfRejectedWhenInFuture(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{
		"iss": "x", "jti": "j",
		"iat": now.Unix(),
		"nbf": now.Add(time.Hour).Unix(),
		"exp": now.Add(2 * time.Hour).Unix(),
	}
	raw, jwks := signECTestStatement(t, "k1", claims, jose.ES256)
	parsed, _ := Parse(raw)
	err := Verify(parsed, []string{"ES256"}, jwks, now)
	if err == nil || err.I18nKey != NotYetValidKey {
		t.Fatalf("want NotYetValid, got %+v", err)
	}
}

func TestVerify_MissingExpRejected(t *testing.T) {
	parsed := &Parsed{
		Header: Header{Alg: "ES256", Kid: "k1"},
		Body:   Body{Iss: "x", Jti: "j", Iat: ptrInt64(time.Now().Unix())},
	}
	err := Verify(parsed, []string{"ES256"}, []byte(`{"keys":[]}`), time.Now())
	if err == nil || err.I18nKey != InvalidStructureKey {
		t.Fatalf("want InvalidStructure (missing exp), got %+v", err)
	}
}

func TestVerify_MissingJtiRejected(t *testing.T) {
	parsed := &Parsed{
		Header: Header{Alg: "ES256", Kid: "k1"},
		Body: Body{
			Iss: "x",
			Iat: ptrInt64(time.Now().Unix()),
			Exp: ptrInt64(time.Now().Add(time.Hour).Unix()),
		},
	}
	err := Verify(parsed, []string{"ES256"}, []byte(`{"keys":[]}`), time.Now())
	if err == nil || err.I18nKey != InvalidStructureKey {
		t.Fatalf("want InvalidStructure (missing jti), got %+v", err)
	}
}

func TestVerify_MissingKidRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	parsed := &Parsed{
		Header: Header{Alg: "ES256"},
		Body: Body{
			Iss: "x", Jti: "j",
			Iat: ptrInt64(now.Unix()),
			Exp: ptrInt64(now.Add(time.Hour).Unix()),
		},
	}
	err := Verify(parsed, []string{"ES256"}, []byte(`{"keys":[]}`), now)
	if err == nil || err.I18nKey != InvalidSignatureKey {
		t.Fatalf("want InvalidSignature (missing kid), got %+v", err)
	}
}

func ptrInt64(v int64) *int64 { return &v }

// strings reference suppresses unused-import lint when this file is the
// only consumer of strings (the helpers below all use it via go-jose).
var _ = strings.TrimSpace

// VerifyAudience truth-table — cavekit-software-statement.md R13 (T-006).
// Six branches: absent / string-match / array-match / string-mismatch /
// array-mismatch / skip-flag-on.

const audTokenEndpoint = "https://issuer.example/oauth/v2/token"

func parsedWithAud(aud any) *Parsed {
	return &Parsed{
		Header: Header{Alg: "ES256", Kid: "k1"},
		Body: Body{
			Iss: "x", Jti: "j",
			Iat: ptrInt64(time.Now().Unix()),
			Exp: ptrInt64(time.Now().Add(time.Hour).Unix()),
			Aud: aud,
		},
	}
}

func TestVerifyAudience_AbsentPasses(t *testing.T) {
	if err := VerifyAudience(parsedWithAud(nil), audTokenEndpoint, false); err != nil {
		t.Fatalf("want nil (absent aud is fine), got %+v", err)
	}
}

func TestVerifyAudience_StringMatchPasses(t *testing.T) {
	if err := VerifyAudience(parsedWithAud(audTokenEndpoint), audTokenEndpoint, false); err != nil {
		t.Fatalf("want nil (string match), got %+v", err)
	}
}

func TestVerifyAudience_ArrayMatchPasses(t *testing.T) {
	aud := []any{"https://other", audTokenEndpoint, "https://yet-another"}
	if err := VerifyAudience(parsedWithAud(aud), audTokenEndpoint, false); err != nil {
		t.Fatalf("want nil (array contains endpoint), got %+v", err)
	}
}

func TestVerifyAudience_StringMismatchRejected(t *testing.T) {
	err := VerifyAudience(parsedWithAud("https://wrong-endpoint"), audTokenEndpoint, false)
	if err == nil || err.I18nKey != InvalidAudienceKey {
		t.Fatalf("want InvalidAudience, got %+v", err)
	}
	if err.Code != "invalid_software_statement" {
		t.Fatalf("want envelope code invalid_software_statement, got %q", err.Code)
	}
}

func TestVerifyAudience_ArrayMismatchRejected(t *testing.T) {
	aud := []any{"https://other", "https://still-wrong"}
	err := VerifyAudience(parsedWithAud(aud), audTokenEndpoint, false)
	if err == nil || err.I18nKey != InvalidAudienceKey {
		t.Fatalf("want InvalidAudience, got %+v", err)
	}
}

func TestVerifyAudience_SkipFlagBypasses(t *testing.T) {
	if err := VerifyAudience(parsedWithAud("https://wrong-endpoint"), audTokenEndpoint, true); err != nil {
		t.Fatalf("want nil (skip flag should bypass), got %+v", err)
	}
	aud := []any{"https://wrong"}
	if err := VerifyAudience(parsedWithAud(aud), audTokenEndpoint, true); err != nil {
		t.Fatalf("want nil (skip flag should bypass for arrays), got %+v", err)
	}
}

// cavekit-software-statement.md R15 (T-024). Empty tokenEndpoint with
// skip=false MUST reject the JWT regardless of `aud` value — defense-
// in-depth against misconfigured pipelines. The Validate() method on
// PipelineDeps SHOULD already have refused to boot, but VerifyAudience
// is the last line of defense.
func TestVerifyAudience_EmptyTokenEndpointRejects(t *testing.T) {
	// aud == "" matches tokenEndpoint == "" trivially; without R15 the
	// switch's `case string: if v == tokenEndpoint { return nil }` would
	// accept. R15 forces a reject.
	if err := VerifyAudience(parsedWithAud(""), "", false); err == nil || err.I18nKey != InvalidAudienceKey {
		t.Fatalf("want InvalidAudience for empty aud + empty tokenEndpoint, got %+v", err)
	}
	// Same for non-empty aud.
	if err := VerifyAudience(parsedWithAud("https://anywhere"), "", false); err == nil || err.I18nKey != InvalidAudienceKey {
		t.Fatalf("want InvalidAudience for any aud when tokenEndpoint is empty, got %+v", err)
	}
}

func stubJTIRecorder(_ context.Context, _, _ string, _, _ time.Time) (JTIRecorderResult, error) {
	return JTIRecorderInserted, nil
}

// PipelineDeps.Validate() must reject the misconfigured combination at
// boot so the empty-tokenEndpoint case never reaches request handling
// in production.
func TestPipelineDepsValidate_EmptyTokenEndpointFailsBoot(t *testing.T) {
	deps := &PipelineDeps{
		JWKSCache:          NewJWKSCache(nil, time.Hour),
		ReplayRecorder:     stubJTIRecorder,
		JTIRetentionBuffer: 24 * time.Hour,
		TokenEndpoint:      "",
		SkipAudValidation:  false,
	}
	if err := deps.Validate(); err == nil {
		t.Fatal("Validate must reject empty TokenEndpoint when SkipAudValidation=false")
	}
	deps.SkipAudValidation = true
	if err := deps.Validate(); err != nil {
		t.Fatalf("Validate must accept empty TokenEndpoint when SkipAudValidation=true; got %v", err)
	}
}
