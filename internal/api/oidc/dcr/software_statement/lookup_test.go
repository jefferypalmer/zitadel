package software_statement

import (
	"strings"
	"testing"
)

func TestLookup_ExactMatch(t *testing.T) {
	cfg := []TrustedIssuer{
		{Issuer: "https://issuer.example.com", JWKSURI: "https://issuer.example.com/jwks", RequiredClaims: []string{"sub"}},
		{Issuer: "https://other.example", JWKSURI: ""},
	}
	got, err := Lookup("https://other.example", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Issuer != "https://other.example" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
	// Returned copy must NOT alias the config's RequiredClaims slice.
	got2, _ := Lookup("https://issuer.example.com", cfg)
	if &got2.RequiredClaims[0] == &cfg[0].RequiredClaims[0] {
		t.Errorf("RequiredClaims aliasing the config slice — caller could mutate config")
	}
}

func TestLookup_CaseSensitive(t *testing.T) {
	cfg := []TrustedIssuer{{Issuer: "https://Issuer.example.com"}}
	_, err := Lookup("https://issuer.example.com", cfg)
	if err == nil {
		t.Fatalf("expected mismatch (case-sensitive)")
	}
	if err.I18nKey != UntrustedIssuerKey {
		t.Errorf("I18nKey = %q", err.I18nKey)
	}
	if err.Code != "unapproved_software_statement" {
		t.Errorf("Code = %q", err.Code)
	}
}

func TestLookup_DescriptionDoesNotEchoIss(t *testing.T) {
	cfg := []TrustedIssuer{{Issuer: "https://allowed.example"}}
	_, err := Lookup("https://attacker-controlled.example/<script>alert(1)</script>", cfg)
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Description, "attacker-controlled") {
		t.Errorf("description echoes offending iss (R3 violation): %q", err.Description)
	}
	if strings.Contains(err.Description, "<script>") {
		t.Errorf("description leaks attacker payload: %q", err.Description)
	}
}

func TestLookup_EmptyTrustedIssuersPreservesPhase1Envelope(t *testing.T) {
	_, err := Lookup("https://anything.example", nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Code != "unapproved_software_statement" {
		t.Errorf("Code = %q, want unapproved_software_statement", err.Code)
	}
}

func TestLookup_EmptyIssRejected(t *testing.T) {
	cfg := []TrustedIssuer{{Issuer: "https://issuer"}}
	_, err := Lookup("", cfg)
	if err == nil || err.Code != "unapproved_software_statement" {
		t.Fatalf("expected unapproved_software_statement, got %+v", err)
	}
}
