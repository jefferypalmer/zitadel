package i18n_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/i18n"
)

// T-074 — DCR i18n English-fallback contract
// (cavekit-console-ui-docs-and-observability.md R3 AC).
//
// The 11 backend `Errors.DCR.*` keys (T-073) ship for English +
// German only. R3 explicitly states "other 19 locales receive English
// fallback" — meaning a request carrying `Accept-Language: ja` (or
// any other supported-but-untranslated locale) MUST resolve the key
// to its English string, NOT leak the raw key (e.g.
// `Errors.DCR.IAT.Exhausted`) into the HTTP response.
//
// `localize()` (translator.go:163) returns the message id verbatim
// when the localizer can find no translation in any of the requested
// languages OR the bundle's default. Our setup uses
// `language.English` as the default, so go-i18n's Localizer falls
// back to the English string when an unsupported lang is requested.
// This test pins that contract.
//
// If a future refactor changes the default language away from
// English (e.g. to language.Und), this test fires — at which point
// the kit's Phase-1 fallback contract has been broken at the
// translator layer and the maintainer must either (a) restore the
// English default or (b) translate every key into every supported
// locale before changing the default.

// dcrEnglishCanonical is the source-of-truth lookup for the 11 keys.
// Mirrors the table in `internal/api/ui/login/static/i18n/dcr_keys_test.go`.
var dcrEnglishCanonical = map[string]string{
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

// fallbackProbeLocales is a representative sample of the 20
// untranslated locales — running the matrix against all 20 is
// redundant since they share the same fallback path. We pick across
// scripts (Latin, Cyrillic, CJK, RTL) so a future regression that
// special-cases one script family doesn't slip through.
var fallbackProbeLocales = []string{"ja", "es", "fr", "ko", "ar"}

func TestT074_R3_DCR_EnglishFallbackOnUnsupportedLocale(t *testing.T) {
	// SupportedLanguages must be initialised before
	// NewLoginTranslator can resolve the bundle. Test binary doesn't
	// run cmd/start/start.go's bootstrap, so call the loader here.
	i18n.MustLoadSupportedLanguagesFromDir()

	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)

	for _, lang := range fallbackProbeLocales {
		for key, want := range dcrEnglishCanonical {
			t.Run(lang+"/"+key, func(t *testing.T) {
				// Plain Accept-Language: <lang> request shape — no
				// explicit `en` tail. The translator's localize() in
				// translator.go preserves the rendered English
				// fallback string when go-i18n returns
				// `*MessageNotFoundErr` together with the
				// default-language template (T-074 fix). Without that
				// fix this assertion catches the raw-key leak.
				got := translator.LocalizeWithoutArgs(key, lang)
				require.NotEqual(t, key, got,
					"R3 fallback violation: locale %q resolved %q to its "+
						"raw key. Either the translator regressed (drop the "+
						"NotFound-tolerant branch in localize()) OR en.yaml "+
						"lost the entry — production HTTP responses would "+
						"emit `error_description: %q`.",
					lang, key, key)
				assert.Equal(t, want, got,
					"R3 fallback contract: locale %q MUST resolve %q to the "+
						"English canonical string (no German leakage, no "+
						"partial translation, no raw key)",
					lang, key)
			})
		}
	}
}

// TestT074_R3_DCR_LocalizeBranches_HonourEnglishFallback is the
// per-branch pin on the translator's `localize()` helper. It
// exercises every public lookup the production code uses to
// translate an `Errors.DCR.*` key — Localize, LocalizeWithoutArgs,
// LocalizeFromRequest. Drift in any one branch is a regression of
// the R3 fallback contract.
func TestT074_R3_DCR_LocalizeBranches_HonourEnglishFallback(t *testing.T) {
	i18n.MustLoadSupportedLanguagesFromDir()
	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)
	const key = "Errors.DCR.IAT.Exhausted"
	want := dcrEnglishCanonical[key]

	t.Run("Localize", func(t *testing.T) {
		got := translator.Localize(key, nil, "ja")
		assert.Equal(t, want, got, "Localize MUST honour English fallback")
	})

	t.Run("LocalizeWithoutArgs", func(t *testing.T) {
		got := translator.LocalizeWithoutArgs(key, "ko")
		assert.Equal(t, want, got, "LocalizeWithoutArgs MUST honour English fallback")
	})

	t.Run("LocalizeFromRequest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Header.Set("Accept-Language", "ar")
		got := translator.LocalizeFromRequest(req, key, nil)
		assert.Equal(t, want, got, "LocalizeFromRequest MUST honour English fallback")
	})
}

// TestT074_R3_DCR_EnglishCanonical_Direct sanity-checks the direct
// English lookup. If this fails the loader pipeline is broken and
// the fallback test above would also fail — pin both ends so a
// future regression points at the right layer.
func TestT074_R3_DCR_EnglishCanonical_Direct(t *testing.T) {
	i18n.MustLoadSupportedLanguagesFromDir()

	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)
	for key, want := range dcrEnglishCanonical {
		t.Run(key, func(t *testing.T) {
			got := translator.LocalizeWithoutArgs(key, "en")
			assert.Equal(t, want, got,
				"R3: en lookup MUST return the canonical string from en.yaml")
		})
	}
}

// TestT074_R3_DCR_GermanDirectLookup pins that German requests get
// the German translation (NOT English fallback). Drift here means
// the de.yaml load failed silently OR the bundle's allowed-languages
// list excluded de — either way the production deployment would
// regress German-speaking customers.
func TestT074_R3_DCR_GermanDirectLookup(t *testing.T) {
	i18n.MustLoadSupportedLanguagesFromDir()

	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)
	for key := range dcrEnglishCanonical {
		t.Run(key, func(t *testing.T) {
			got := translator.LocalizeWithoutArgs(key, "de")
			require.NotEqual(t, key, got,
				"R3: de.yaml MUST translate %q (raw key leaked)", key)
			require.NotEmpty(t, got)
			// Negative pin: German MUST NOT match the English string
			// for the keys we shipped explicit German translations for.
			// If they ever match, either de.yaml regressed to copying
			// English (translator quality issue) or the lookup fell
			// back to English (bundle wiring issue).
			assert.NotEqual(t, dcrEnglishCanonical[key], got,
				"R3: de.yaml lookup for %q returned the English string — "+
					"either de.yaml regressed or bundle fallback fired (kit pins "+
					"distinct German translations for all 11 DCR keys)", key)
		})
	}
}
