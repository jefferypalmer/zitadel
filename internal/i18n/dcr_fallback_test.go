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
// As of T-075 every supported locale ships its own translation of the
// 11 backend `Errors.DCR.*` keys, so the original "ja → English
// fallback" probe no longer holds (ja resolves to its own translation).
// The fallback CONTRACT — "an unsupported locale MUST resolve to the
// English string, never the raw translation key" — still matters for
// any future locale-tag the bundle has not seen, so this file pins
// it via:
//
//   1. A synthetic locale tag (`zz`) the bundle has not loaded — the
//      only way to exercise go-i18n's MessageNotFoundErr path now
//      that every loaded locale ships translations.
//   2. Every loaded supported locale (de + 20 translated locales)
//      MUST resolve every DCR key to a non-empty, non-raw-key, non-
//      English (where applicable per T-075) string.
//
// `localize()` (translator.go) returns the message id verbatim only
// when the localizer can find no translation in any of the requested
// languages AND the bundle's default language. The T-074 patch made
// that branch tolerate `*MessageNotFoundErr` carrying a non-empty
// rendered English fallback; the synthetic-locale test below pins
// that branch directly.

// dcrEnglishCanonical is the source-of-truth lookup for the 11 keys.
// Mirrors the table in `dcr_keys_test.go` in this package.
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

// translatedLocales is the set of locales beyond English that ship
// hand-translated DCR strings (T-073 + T-075). Each MUST resolve every
// DCR key to a non-empty, non-raw-key, non-English string.
var translatedLocales = []string{
	"de", "ar", "bg", "cs", "es", "fr", "hu", "id", "it", "ja",
	"ko", "mk", "nl", "pl", "pt", "ro", "ru", "sv", "tr", "uk", "zh",
}

// TestT074_R3_DCR_FallbackToEnglish_OnUnloadedLocale pins the
// fallback CONTRACT — go-i18n's *MessageNotFoundErr path MUST
// preserve the rendered English fallback string instead of leaking
// the raw key. We exercise this with a synthetic locale tag (`zz`)
// that the bundle has not loaded; every other supported locale
// ships its own translation post-T-075 and would no longer fall
// back at all.
func TestT074_R3_DCR_FallbackToEnglish_OnUnloadedLocale(t *testing.T) {
	i18n.MustLoadSupportedLanguagesFromDir()
	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)
	const unloadedTag = "zz" // ISO 639 reserved-private; never present in i18n/.
	for key, want := range dcrEnglishCanonical {
		t.Run(key, func(t *testing.T) {
			got := translator.LocalizeWithoutArgs(key, unloadedTag)
			require.NotEqual(t, key, got,
				"R3 fallback violation: unloaded locale %q resolved %q to its "+
					"raw key. The translator's MessageNotFoundErr-tolerant "+
					"branch in localize() (T-074 patch) regressed — production "+
					"would emit `error_description: %q`.",
				unloadedTag, key, key)
			assert.Equal(t, want, got,
				"R3 fallback contract: unloaded locale %q MUST resolve %q to "+
					"the English canonical string (no partial translation, no raw key)",
				unloadedTag, key)
		})
	}
}

// TestT074_R3_DCR_LocalizeBranches_HonourFallback pins the same
// fallback contract through every public lookup branch the
// production code uses. Drift in any one branch is a regression.
func TestT074_R3_DCR_LocalizeBranches_HonourFallback(t *testing.T) {
	i18n.MustLoadSupportedLanguagesFromDir()
	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)
	const key = "Errors.DCR.IAT.Exhausted"
	want := dcrEnglishCanonical[key]
	const unloadedTag = "zz"

	t.Run("Localize", func(t *testing.T) {
		got := translator.Localize(key, nil, unloadedTag)
		assert.Equal(t, want, got, "Localize MUST honour English fallback")
	})

	t.Run("LocalizeWithoutArgs", func(t *testing.T) {
		got := translator.LocalizeWithoutArgs(key, unloadedTag)
		assert.Equal(t, want, got, "LocalizeWithoutArgs MUST honour English fallback")
	})

	t.Run("LocalizeFromRequest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Header.Set("Accept-Language", unloadedTag)
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

// TestT075_R3_DCR_AllSupportedLocales_ResolveDistinct pins that every
// loaded supported locale (de + 20 T-075 translations) resolves every
// DCR key to a non-empty, non-raw-key, non-English string. Drift here
// means either the locale's yaml regressed (key removed or copied
// English text) OR the translator fell back to English when it
// shouldn't have.
func TestT075_R3_DCR_AllSupportedLocales_ResolveDistinct(t *testing.T) {
	i18n.MustLoadSupportedLanguagesFromDir()
	translator := i18n.NewLoginTranslator(
		language.English,
		i18n.SupportedLanguages(),
		"",
	)
	for _, locale := range translatedLocales {
		for key, english := range dcrEnglishCanonical {
			t.Run(locale+"/"+key, func(t *testing.T) {
				got := translator.LocalizeWithoutArgs(key, locale)
				require.NotEmpty(t, got)
				require.NotEqual(t, key, got,
					"R3 (T-075): locale %q resolved %q to the raw key — "+
						"the locale's Errors.DCR.* block is missing or "+
						"the translator regressed",
					locale, key)
				assert.NotEqual(t, english, got,
					"R3 (T-075): locale %q resolved %q to the English string — "+
						"either the yaml regressed to copying English or "+
						"the bundle fell back unexpectedly",
					locale, key)
			})
		}
	}
}
