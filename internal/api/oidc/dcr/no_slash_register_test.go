package dcr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStripPrefixEmptyPath_NormalizationFix pins the load-bearing
// invariant: when `apis.RegisterHandlerOnPrefix("/oidc/v1/register",
// dcrHandler)` strips the prefix and the request URL was
// `/oidc/v1/register` (no trailing slash), the path passed to the
// inner DCR handler is the empty string. Gorilla mux treats both
// `r.HandleFunc("", ...)` and `r.HandleFunc("/", ...)` as the same
// pattern, so an empty post-strip path matches NEITHER. Without the
// path-normalization wrapper in NewHandler, the parent mux would fall
// through to the catch-all login handler at `/`, which 301-redirects
// to `/` — corrupting POST bodies in clients without `-L`.
//
// This test rebuilds the StripPrefix + path-normalize + gorilla
// pipeline from scratch with a single trivial route registered on
// `/`. The contract: both `/oidc/v1/register` and `/oidc/v1/register/`
// reach the inner handler with no redirect.
func TestStripPrefixEmptyPath_NormalizationFix(t *testing.T) {
	const prefix = "/oidc/v1/register"
	var hits int
	var lastPath string

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		hits++
		lastPath = req.URL.Path
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodPost)

	// The same wrapper shape NewHandler uses in production: normalize
	// the empty path to "/" so the gorilla router below matches.
	normalized := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		r.ServeHTTP(w, req)
	})

	mounted := http.StripPrefix(prefix, normalized)

	cases := []struct {
		name string
		url  string
	}{
		{"with trailing slash", prefix + "/"},
		{"without trailing slash", prefix},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := hits
			req := httptest.NewRequest(http.MethodPost,
				"http://localhost"+c.url,
				strings.NewReader(`{"smoke":true}`))
			rec := httptest.NewRecorder()
			mounted.ServeHTTP(rec, req)

			require.NotEqual(t, http.StatusMovedPermanently, rec.Code,
				"%s: 301 redirect — Location: %q. The handler did not match the post-StripPrefix path; gorilla mux fell through.",
				c.name, rec.Header().Get("Location"))
			require.NotEqual(t, http.StatusNotFound, rec.Code,
				"%s: 404 — the gorilla mux pattern did not match an empty/normalized path",
				c.name)
			assert.Equal(t, http.StatusOK, rec.Code, "%s: expected 200 from inner handler", c.name)
			assert.Equal(t, before+1, hits, "%s: handler must run exactly once", c.name)
			assert.Equal(t, "/", lastPath,
				"%s: inner handler must see normalized path '/' regardless of trailing-slash form",
				c.name)
		})
	}
}
