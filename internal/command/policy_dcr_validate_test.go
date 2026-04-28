package command

import (
	"strings"
	"testing"
	"time"
)

// cavekit-org-dcr-policy.md R4 / T-018 — set-narrowing semantics.
func TestValidateOrgAllowedAudiencesSubset(t *testing.T) {
	instance := []string{"https://api.example.com", "https://other.example"}
	tests := []struct {
		name        string
		org         []string
		instance    []string
		wantErr     bool
		errContains string
	}{
		{name: "empty org list (= inherit) passes", org: nil, instance: instance},
		{name: "valid subset passes", org: []string{"https://api.example.com"}, instance: instance},
		{name: "exact match passes", org: instance, instance: instance},
		{
			name:        "out of bounds (URI not in instance) refused",
			org:         []string{"https://api.example.com", "https://attacker.example"},
			instance:    instance,
			wantErr:     true,
			errContains: "https://attacker.example",
		},
		{
			name:        "first violating URI named (only the first)",
			org:         []string{"https://first-bad.example", "https://second-bad.example"},
			instance:    instance,
			wantErr:     true,
			errContains: "first-bad",
		},
		{
			name:     "empty instance list (unrestricted) accepts any valid URI",
			org:      []string{"https://anything.example"},
			instance: nil,
		},
		{
			name:        "non-absolute URI refused",
			org:         []string{"/relative/path"},
			instance:    nil,
			wantErr:     true,
			errContains: "absolute URI",
		},
		{
			name:        "URI with fragment refused",
			org:         []string{"https://api.example.com/#frag"},
			instance:    nil,
			wantErr:     true,
			errContains: "fragment",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOrgAllowedAudiencesSubset(tc.org, tc.instance)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("err %q lacks %q", err.Error(), tc.errContains)
			}
		})
	}
}

// First-violating only — second invalid URI must NOT appear in description.
func TestValidateOrgAllowedAudiencesSubset_OnlyFirstNamed(t *testing.T) {
	err := validateOrgAllowedAudiencesSubset(
		[]string{"https://first.example", "https://second.example"},
		[]string{"https://only.example"},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "first.example") {
		t.Errorf("first violating URI not named: %v", err)
	}
	if strings.Contains(err.Error(), "second.example") {
		t.Errorf("second URI leaked into error: %v", err)
	}
}

// cavekit-org-dcr-policy.md R5 / T-019 — cap-narrowing semantics.
func TestValidateOrgLifetimeCap(t *testing.T) {
	tests := []struct {
		name        string
		org         time.Duration
		instance    time.Duration
		wantErr     bool
		errContains string
	}{
		{name: "org < instance (positive cap) passes", org: 1 * time.Hour, instance: 24 * time.Hour},
		{name: "org == instance (positive cap) passes", org: 24 * time.Hour, instance: 24 * time.Hour},
		{
			name:        "org > instance refused",
			org:         48 * time.Hour,
			instance:    24 * time.Hour,
			wantErr:     true,
			errContains: "exceeds instance cap",
		},
		{name: "instance 0s (no expiry) admits any positive org", org: 24 * time.Hour, instance: 0},
		{name: "instance 0s admits org 0s", org: 0, instance: 0},
		{
			name:        "instance positive + org 0s refused (no-expiry cannot widen finite cap)",
			org:         0,
			instance:    24 * time.Hour,
			wantErr:     true,
			errContains: "no expiry",
		},
		{
			name:        "negative org refused",
			org:         -1 * time.Hour,
			instance:    24 * time.Hour,
			wantErr:     true,
			errContains: "negative",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOrgLifetimeCap(tc.org, tc.instance)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("err %q lacks %q", err.Error(), tc.errContains)
			}
		})
	}
}
