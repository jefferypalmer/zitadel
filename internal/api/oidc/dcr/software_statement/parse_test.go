package software_statement

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// makeJWT builds a `header.body.sig` string with the supplied JSON
// fragments (or raw base64 segments via the *Raw helpers below).
// Signature segment is a fixed placeholder — Parse never inspects it.
func makeJWT(headerJSON, bodyJSON string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	b := base64.RawURLEncoding.EncodeToString([]byte(bodyJSON))
	return h + "." + b + ".AAAA"
}

func TestParse_EmptyInputReturnsNil(t *testing.T) {
	got, err := Parse("")
	if err != nil || got != nil {
		t.Fatalf("Parse(\"\") = %v, %v; want nil, nil", got, err)
	}
}

func TestParse_StructuralFailures(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantSubstr string
	}{
		{"two segments", "a.b", "3-segment JWT"},
		{"four segments", "a.b.c.d", "3-segment JWT"},
		{"empty header segment", ".body.sig", "segment 0 is empty"},
		{"empty body segment", "header..sig", "segment 1 is empty"},
		{
			name:       "invalid base64 header",
			input:      "!!!." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + ".sig",
			wantSubstr: "header is not valid base64url",
		},
		{
			name: "invalid JSON header",
			input: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":`)) +
				"." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + ".sig",
			wantSubstr: "header is not valid JSON",
		},
		{
			name:       "missing alg",
			input:      makeJWT(`{}`, `{"iss":"https://issuer"}`),
			wantSubstr: "header `alg` is required",
		},
		{
			name:       "missing iss",
			input:      makeJWT(`{"alg":"RS256"}`, `{"jti":"x"}`),
			wantSubstr: "`iss` is required",
		},
		{
			name:       "invalid JSON body",
			input:      makeJWT(`{"alg":"RS256"}`, `{`),
			wantSubstr: "body is not valid JSON",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if got != nil {
				t.Fatalf("got non-nil result on failure: %+v", got)
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSubstr)
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("expected *ParseError, got %T", err)
			}
			if pe.Code != "invalid_software_statement" {
				t.Errorf("Code = %q, want invalid_software_statement", pe.Code)
			}
			if pe.I18nKey != InvalidStructureKey {
				t.Errorf("I18nKey = %q, want %q", pe.I18nKey, InvalidStructureKey)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q lacks substring %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

func TestParse_BodySizeCap(t *testing.T) {
	huge := strings.Repeat("a", MaxSoftwareStatementBytes+1)
	_, err := Parse(huge)
	if err == nil {
		t.Fatalf("expected size-cap error")
	}
	if !strings.Contains(err.Error(), "size exceeds") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestParse_HappyPathPreservesExtraClaims(t *testing.T) {
	header := `{"alg":"RS256","kid":"k1"}`
	body := `{"iss":"https://issuer","jti":"j1","exp":1700000000,"redirect_uris":["https://app.example/cb"]}`
	got, err := Parse(makeJWT(header, body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Header.Alg != "RS256" || got.Header.Kid != "k1" {
		t.Errorf("header decoded wrong: %+v", got.Header)
	}
	if got.Body.Iss != "https://issuer" || got.Issuer != "https://issuer" {
		t.Errorf("issuer decoded wrong: body.Iss=%q issuer=%q", got.Body.Iss, got.Issuer)
	}
	if got.Body.Jti != "j1" {
		t.Errorf("jti = %q", got.Body.Jti)
	}
	if got.Body.Exp == nil || *got.Body.Exp != 1700000000 {
		t.Errorf("exp not preserved: %v", got.Body.Exp)
	}
	uris, ok := got.Body.Extra["redirect_uris"]
	if !ok {
		t.Fatalf("redirect_uris not preserved in Extra")
	}
	var decoded []string
	if err := json.Unmarshal(uris, &decoded); err != nil {
		t.Fatalf("redirect_uris not valid JSON: %v", err)
	}
	if len(decoded) != 1 || decoded[0] != "https://app.example/cb" {
		t.Errorf("redirect_uris = %v", decoded)
	}
	// Standard claims should NOT bleed into Extra.
	for _, k := range []string{"iss", "aud", "exp", "nbf", "iat", "jti", "sub"} {
		if _, present := got.Body.Extra[k]; present {
			t.Errorf("standard claim %q leaked into Extra", k)
		}
	}
}
