package i18n_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// T-073 — Backend `Errors.DCR.*` i18n key set
// (cavekit-console-ui-docs-and-observability.md R3 AC4).
//
// The YAML files are statik-embedded into the binary; this test
// validates them as data so a future refactor of the translator or
// statik build cannot silently drop a key. A missing key on the live
// translator yields a raw-key leak in production HTTP responses
// (e.g. `error_description: "Errors.DCR.IAT.Exhausted"`) — the
// `dcr_i18n_fallback_test.go` integration test (T-074) is the
// runtime backstop; this is the source-of-truth pin.
//
// Required keys are enumerated literally (not derived) so a
// rename / removal is visible in the diff of THIS file rather than
// hiding inside a yaml refactor.

var requiredEnglishStrings = map[string]string{
	"Errors.DCR.FeatureDisabled":             "Dynamic client registration is disabled.",
	"Errors.DCR.InvalidClientMetadata":       "Invalid client metadata.",
	"Errors.DCR.InvalidRedirectURI":          "Invalid redirect URI.",
	"Errors.DCR.InvalidSoftwareStatement":    "Invalid software statement.",
	"Errors.DCR.UnapprovedSoftwareStatement": "Software statement is not approved.",
	"Errors.DCR.InvalidToken":                "Invalid or missing access token.",
	"Errors.DCR.IAT.Exhausted":               "Initial access token is exhausted.",
	"Errors.DCR.IAT.SlotAlreadyConsumed":     "Initial access token slot already consumed.",
	"Errors.DCR.IAT.NotFound":                "Initial access token not found.",
	"Errors.DCR.IAT.Expired":                 "Initial access token expired.",
	"Errors.DCR.IAT.Revoked":                 "Initial access token has been revoked.",
}

func TestT073_R3_AC4_DCRBackendKeys_EnglishCanonical(t *testing.T) {
	tree := loadI18nYAML(t, "en.yaml")
	for key, want := range requiredEnglishStrings {
		t.Run(key, func(t *testing.T) {
			got, ok := lookupDottedKey(tree, key)
			require.True(t, ok,
				"R3 AC4: en.yaml MUST define %q — without it production "+
					"emits the raw translation key as error_description", key)
			assert.Equal(t, want, got,
				"R3 AC4: en.yaml value drift for %q — kit pins the canonical English string", key)
		})
	}
}

func TestT073_R3_AC4_DCRBackendKeys_GermanTranslated(t *testing.T) {
	tree := loadI18nYAML(t, "de.yaml")
	// German translation values are pinned by presence + non-emptiness;
	// pinning the literal string would couple this test to translator
	// review wording, which the build site explicitly hands off to the
	// `@zitadel/i18n` team via T-075. Presence+non-empty is the
	// invariant T-073 owns.
	for key := range requiredEnglishStrings {
		t.Run(key, func(t *testing.T) {
			got, ok := lookupDottedKey(tree, key)
			require.True(t, ok,
				"R3 AC4: de.yaml MUST define %q (English fallback NOT acceptable here — "+
					"German is one of the two Phase-1 supported locales)", key)
			require.NotEmpty(t, got,
				"R3 AC4: de.yaml value for %q MUST be non-empty (raw-key emission guard)", key)
		})
	}
}

func TestT073_R3_AC4_DCRBackendKeys_NotInUnsupportedLocales(t *testing.T) {
	// R3 wording: "other 19 locales receive English fallback" — i.e.
	// the DCR keys MUST NOT be present in any locale beyond en + de
	// for Phase 1 (T-075 opens the translation tickets to reach
	// completeness). Drift here means a contributor translated DCR
	// strings ahead of the team-coordination workflow, which the
	// fallback test in T-074 will then NOT exercise.
	otherLocales := []string{
		"ar.yaml", "bg.yaml", "cs.yaml", "es.yaml", "fr.yaml", "hu.yaml",
		"id.yaml", "it.yaml", "ja.yaml", "ko.yaml", "mk.yaml", "nl.yaml",
		"pl.yaml", "pt.yaml", "ro.yaml", "ru.yaml", "sv.yaml", "tr.yaml",
		"uk.yaml", "zh.yaml",
	}
	for _, name := range otherLocales {
		t.Run(name, func(t *testing.T) {
			tree := loadI18nYAML(t, name)
			// Look up the parent path. If `Errors.DCR` itself is absent,
			// the locale is in the documented Phase-1 fallback state
			// (correct). If present, fail and point at T-075.
			if _, ok := lookupDottedKey(tree, "Errors.DCR.FeatureDisabled"); ok {
				t.Fatalf("R3 AC4: %s contains DCR translations ahead of T-075 — "+
					"if you are submitting Phase-1+ DCR translations, also extend "+
					"requiredEnglishStrings above to pin every key",
					name)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────

func loadI18nYAML(t *testing.T, name string) map[string]any {
	t.Helper()
	path := filepath.Join("../api/ui/login/static/i18n", name)
	data, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err, "loadI18nYAML(%s)", name)
	var out map[string]any
	require.NoError(t, yaml.Unmarshal(data, &out), "yaml.Unmarshal(%s)", name)
	return out
}

// lookupDottedKey walks `Errors.DCR.IAT.Exhausted` style paths through
// a yaml-decoded map[string]any tree. Returns the leaf string when
// the path resolves to a string node; (zero, false) otherwise.
func lookupDottedKey(tree map[string]any, dotted string) (string, bool) {
	parts := splitDot(dotted)
	cur := any(tree)
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		next, found := m[p]
		if !found {
			return "", false
		}
		cur = next
	}
	s, ok := cur.(string)
	return s, ok
}

func splitDot(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
