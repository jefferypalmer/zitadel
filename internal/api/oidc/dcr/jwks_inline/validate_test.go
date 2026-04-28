package jwks_inline

import (
	"encoding/json"
	"strings"
	"testing"
)

// goodEC is a syntactically valid (cryptographically irrelevant) EC JWK
// reused across success-path tests. Only the public fields are present.
const goodEC = `{"kty":"EC","crv":"P-256","kid":"k1","x":"abc","y":"def","alg":"ES256"}`

func wrap(keys ...string) string {
	return `{"keys":[` + strings.Join(keys, ",") + `]}`
}

func TestValidate_HappyPath(t *testing.T) {
	canonical, err := Validate(json.RawMessage(wrap(goodEC)))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.HasPrefix(string(canonical), `{"keys":[`) {
		t.Fatalf("canonical missing wrapper: %s", canonical)
	}
	// Sanity: canonical key bytes are sorted-key — `alg` precedes `crv`.
	if !strings.Contains(string(canonical), `"alg":"ES256","crv":"P-256"`) {
		t.Fatalf("expected sorted-key encoding, got: %s", canonical)
	}
}

func TestValidate_FailureMatrix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey string
	}{
		{"empty input", "", KeyInvalidStructure},
		{"non-object", "[]", KeyInvalidStructure},
		{"missing keys field", "{}", KeyInvalidStructure},
		{"keys is non-array", `{"keys":"x"}`, KeyInvalidStructure},
		{"empty keys array", `{"keys":[]}`, KeyEmptyKeySet},
		{
			name:    "missing kid",
			input:   wrap(`{"kty":"EC","crv":"P-256","x":"a","y":"b"}`),
			wantKey: KeyInvalidStructure,
		},
		{
			name:    "duplicate kid",
			input:   wrap(goodEC, `{"kty":"EC","crv":"P-256","kid":"k1","x":"x","y":"y"}`),
			wantKey: KeyDuplicateKid,
		},
		{
			name:    "unsupported kty",
			input:   wrap(`{"kty":"oct","kid":"k1","k":"abc"}`),
			wantKey: KeyInvalidStructure,
		},
		{
			name:    "unsupported alg",
			input:   wrap(`{"kty":"EC","crv":"P-256","kid":"k1","x":"a","y":"b","alg":"none"}`),
			wantKey: KeyUnsupportedAlgorithm,
		},
		{
			name:    "private material `d`",
			input:   wrap(`{"kty":"EC","crv":"P-256","kid":"k1","x":"a","y":"b","d":"PRIVATE"}`),
			wantKey: KeyPrivateKeyMaterial,
		},
		{
			name:    "private material `p`",
			input:   wrap(`{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB","p":"P"}`),
			wantKey: KeyPrivateKeyMaterial,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(json.RawMessage(tc.input))
			if err == nil {
				t.Fatalf("expected error")
			}
			if err.I18nKey != tc.wantKey {
				t.Errorf("I18nKey = %q, want %q (desc: %s)", err.I18nKey, tc.wantKey, err.Description)
			}
		})
	}
}

func TestValidate_TooManyKeys(t *testing.T) {
	keys := make([]string, 0, MaxKeys+1)
	for i := 0; i <= MaxKeys; i++ {
		keys = append(keys, `{"kty":"EC","crv":"P-256","kid":"k`+itoa(i)+`","x":"a","y":"b"}`)
	}
	_, err := Validate(json.RawMessage(wrap(keys...)))
	if err == nil || err.I18nKey != KeyTooManyKeys {
		t.Fatalf("want TooManyKeys, got %+v", err)
	}
}

func TestValidate_TooLarge(t *testing.T) {
	bigX := strings.Repeat("a", MaxSerializedBytes+10)
	in := wrap(`{"kty":"EC","crv":"P-256","kid":"k1","x":"` + bigX + `","y":"b"}`)
	_, err := Validate(json.RawMessage(in))
	if err == nil || err.I18nKey != KeyTooLarge {
		t.Fatalf("want TooLarge, got %+v", err)
	}
}

func TestValidate_DropsUseEncSilently(t *testing.T) {
	encKey := `{"kty":"EC","crv":"P-256","kid":"enc1","x":"a","y":"b","use":"enc"}`
	canonical, err := Validate(json.RawMessage(wrap(goodEC, encKey)))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if strings.Contains(string(canonical), `"enc1"`) {
		t.Errorf("use=enc key was retained in canonical form: %s", canonical)
	}
}

func TestValidate_AllEncKeysIsEmpty(t *testing.T) {
	encKey := `{"kty":"EC","crv":"P-256","kid":"enc1","x":"a","y":"b","use":"enc"}`
	_, err := Validate(json.RawMessage(wrap(encKey)))
	if err == nil || err.I18nKey != KeyEmptyKeySet {
		t.Fatalf("want EmptyKeySet after dropping all enc keys, got %+v", err)
	}
}

// itoa is a local minimal int-to-string to avoid pulling in strconv into
// the test file just for this loop.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
