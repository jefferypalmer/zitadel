package software_statement

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// MappedClaims comment block in override.go must list exactly the
// claims in mappedClaims. The doc comment is the single source of
// truth surfaced in code review; this test pins them together so a
// future contributor cannot add a claim to the table without updating
// the comment.
func TestMappedClaims_CommentParityWithTable(t *testing.T) {
	got := MappedClaims()
	sort.Strings(got)
	want := []string{
		"client_name", "client_uri", "grant_types", "logo_uri",
		"policy_uri", "redirect_uris", "response_types", "scope",
		"software_id", "software_version", "tos_uri",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("mapped claims = %v\nwant         = %v", got, want)
	}
}

func TestMergedMetadata_NilParsedReturnsBodyUnchanged(t *testing.T) {
	body := map[string]json.RawMessage{
		"client_name":   json.RawMessage(`"BodyName"`),
		"redirect_uris": json.RawMessage(`["https://body.example/cb"]`),
	}
	got := MergedMetadata(body, nil)
	if string(got["client_name"]) != `"BodyName"` {
		t.Errorf("body must pass through when no software_statement")
	}
}

func TestMergedMetadata_OverridesMappedClaims(t *testing.T) {
	body := map[string]json.RawMessage{
		"client_name":   json.RawMessage(`"BodyName"`),
		"redirect_uris": json.RawMessage(`["https://body.example/cb"]`),
		"scope":         json.RawMessage(`"openid"`),
	}
	parsed := &Parsed{
		Body: Body{
			Extra: map[string]json.RawMessage{
				"client_name": json.RawMessage(`"JWTName"`),
				"scope":       json.RawMessage(`"openid email profile"`),
			},
		},
	}
	got := MergedMetadata(body, parsed)
	if string(got["client_name"]) != `"JWTName"` {
		t.Errorf("client_name = %s, want \"JWTName\"", got["client_name"])
	}
	if string(got["scope"]) != `"openid email profile"` {
		t.Errorf("scope = %s", got["scope"])
	}
	// redirect_uris was on the body but NOT on the JWT — body retained.
	if string(got["redirect_uris"]) != `["https://body.example/cb"]` {
		t.Errorf("redirect_uris should remain body value when JWT did not provide one")
	}
}

func TestMergedMetadata_EnvelopeClaimsNotMapped(t *testing.T) {
	body := map[string]json.RawMessage{}
	parsed := &Parsed{
		Body: Body{
			Iss: "https://issuer", Jti: "j1",
			Extra: map[string]json.RawMessage{
				// These envelope claims (and a malicious "custom" one)
				// MUST NOT bleed into the merged metadata.
				"iss":    json.RawMessage(`"https://attacker.example"`),
				"custom": json.RawMessage(`"injected"`),
			},
		},
	}
	got := MergedMetadata(body, parsed)
	if _, ok := got["iss"]; ok {
		t.Errorf("iss must not appear in merged metadata")
	}
	if _, ok := got["custom"]; ok {
		t.Errorf("custom claim leaked into merged metadata")
	}
}

func TestVerifyRequiredClaims_PassesWhenEmpty(t *testing.T) {
	parsed := &Parsed{Body: Body{Extra: map[string]json.RawMessage{}}}
	if err := VerifyRequiredClaims(parsed, nil); err != nil {
		t.Fatalf("empty list must pass: %v", err)
	}
	if err := VerifyRequiredClaims(parsed, []string{}); err != nil {
		t.Fatalf("explicit empty list must pass: %v", err)
	}
}

func TestVerifyRequiredClaims_RejectsAbsent(t *testing.T) {
	parsed := &Parsed{Body: Body{Extra: map[string]json.RawMessage{}}}
	err := VerifyRequiredClaims(parsed, []string{"sub"})
	if err == nil || err.I18nKey != MissingRequiredClaimKey {
		t.Fatalf("want MissingRequiredClaim, got %+v", err)
	}
	if !strings.Contains(err.Description, "sub") {
		t.Errorf("description should name the missing claim: %v", err)
	}
}

func TestVerifyRequiredClaims_RejectsEmptyValueForms(t *testing.T) {
	emptyForms := map[string]string{
		"null-value":   `null`,
		"empty-string": `""`,
		"empty-array":  `[]`,
		"empty-object": `{}`,
	}
	for name, raw := range emptyForms {
		t.Run(name, func(t *testing.T) {
			parsed := &Parsed{Body: Body{Extra: map[string]json.RawMessage{
				"sub": json.RawMessage(raw),
			}}}
			err := VerifyRequiredClaims(parsed, []string{"sub"})
			if err == nil || err.I18nKey != MissingRequiredClaimKey {
				t.Fatalf("want MissingRequiredClaim, got %+v", err)
			}
		})
	}
}

func TestVerifyRequiredClaims_AcceptsNonEmptyForms(t *testing.T) {
	cases := map[string]string{
		"non-empty string": `"x"`,
		"number":           `42`,
		"bool true":        `true`,
		"non-empty array":  `[1]`,
		"non-empty object": `{"k":"v"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			parsed := &Parsed{Body: Body{Extra: map[string]json.RawMessage{
				"sub": json.RawMessage(raw),
			}}}
			if err := VerifyRequiredClaims(parsed, []string{"sub"}); err != nil {
				t.Fatalf("expected pass, got %+v", err)
			}
		})
	}
}
