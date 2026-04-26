package dcr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// JwksFetcherConfig is the runtime configuration for the SSRF-guarded
// JWKS fetcher. Populated from `OIDC.DCR.JwksURI.*` in
// cmd/defaults.yaml (cavekit-config.md R1) and
// cavekit-security-hardening.md R2.
type JwksFetcherConfig struct {
	// HTTPTimeout caps the entire fetch (connect + redirects + body
	// read). Default 10s.
	HTTPTimeout time.Duration

	// AllowLoopbackInDev removes 127.0.0.0/8 and ::1/128 from the
	// effective deny-list. MUST stay false in production. Set true
	// only in dev / integration test config.
	AllowLoopbackInDev bool

	// DisallowedIPRanges in CIDR notation. Every IP the fetcher
	// resolves (initial + each redirect target) is checked against
	// these; matches are refused.
	DisallowedIPRanges []string
}

// MaxRedirects is the SSRF redirect cap from cavekit-security-hardening.md
// R2 acceptance criterion 4 ("Redirects are followed at most 3 hops").
const MaxRedirects = 3

// MaxBodyBytes caps the response size at 1 MiB (R2 criterion 5 —
// "Response body size cap: 1 MiB; oversized responses fail").
const MaxBodyBytes = 1 << 20

// JwksFetcher fetches the bytes at a `jwks_uri` while enforcing the
// SSRF defenses required by cavekit-security-hardening.md R2:
//
//   - IP-range deny-list enforced on the initial host AND every
//     redirect target;
//   - DNS-rebind mitigation: hostname is resolved exactly once per
//     hop and the dialer connects to that resolved IP (no second
//     resolution that could return a different address);
//   - at most MaxRedirects (=3) redirect hops;
//   - response body is hard-capped at MaxBodyBytes (=1 MiB);
//   - HTTPTimeout (default 10s) bounds the total fetch duration.
//
// The fetcher does NOT parse or validate JWKS content — it only
// returns the raw bytes. JWKS parsing/validation is the caller's
// concern (T-036).
type JwksFetcher struct {
	cfg     JwksFetcherConfig
	denied  []netip.Prefix
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewJwksFetcher returns a fetcher honoring cfg. Returns an error if
// any DisallowedIPRanges entry is unparseable.
func NewJwksFetcher(cfg JwksFetcherConfig) (*JwksFetcher, error) {
	denied, err := parseDeniedRanges(cfg.DisallowedIPRanges, cfg.AllowLoopbackInDev)
	if err != nil {
		return nil, err
	}
	return &JwksFetcher{
		cfg:     cfg,
		denied:  denied,
		resolve: defaultResolve,
		dial:    defaultDial,
	}, nil
}

// Fetch retrieves the JWKS document at jwksURI. Returns the raw body
// bytes (≤ MaxBodyBytes) on success, or an error describing the
// specific SSRF gate that triggered (or the underlying network/HTTP
// failure).
func (f *JwksFetcher) Fetch(ctx context.Context, jwksURI string) ([]byte, error) {
	if f.cfg.HTTPTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.cfg.HTTPTimeout)
		defer cancel()
	}

	currentURL := jwksURI
	for hop := 0; hop <= MaxRedirects; hop++ {
		resp, err := f.do(ctx, currentURL)
		if err != nil {
			return nil, err
		}

		if !isRedirect(resp.StatusCode) {
			defer resp.Body.Close()
			return readCappedBody(resp.Body)
		}

		// Redirect — record the new target, close the current body,
		// and re-validate at the next loop iteration.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil, errors.New("dcr/jwks: redirect response missing Location header")
		}

		next, err := resolveRedirect(currentURL, loc)
		if err != nil {
			return nil, fmt.Errorf("dcr/jwks: invalid redirect Location: %w", err)
		}
		currentURL = next
	}

	return nil, fmt.Errorf("dcr/jwks: redirect cap exceeded (max=%d hops)", MaxRedirects)
}

// do issues a single HTTP request with SSRF guards: scheme + IP
// resolution + connect-to-resolved-IP. It returns the raw response
// (caller closes the body).
func (f *JwksFetcher) do(ctx context.Context, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("dcr/jwks: invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("dcr/jwks: scheme %q not allowed (must be http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("dcr/jwks: URL %q has empty host", rawURL)
	}

	// Resolve once — DNS-rebind mitigation. The resolved IPs are
	// checked against the deny-list; the FIRST allowed address is the
	// one we connect to via custom dialer. The library's net/http
	// Transport will not re-resolve because we override DialContext.
	addrs, err := f.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dcr/jwks: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dcr/jwks: %q resolved to zero addresses", host)
	}
	var pinned netip.Addr
	for _, a := range addrs {
		if f.isDenied(a) {
			return nil, fmt.Errorf("dcr/jwks: %q resolved to a disallowed address %s", host, a)
		}
		if !pinned.IsValid() {
			pinned = a
		}
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pinnedAddr := net.JoinHostPort(pinned.String(), port)

	transport := &http.Transport{
		// Pin the dialer to the resolved IP. host:port from the URL is
		// IGNORED here — we always go to pinnedAddr. This is the
		// DNS-rebind defense.
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return f.dial(dialCtx, network, pinnedAddr)
		},
		// The TLS hostname must still be the URL's hostname (cert
		// validation). net/http handles this via the Host header.
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: f.cfg.HTTPTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   f.cfg.HTTPTimeout,
		// We handle redirects ourselves (per-hop SSRF re-validation).
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dcr/jwks: new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	return client.Do(req)
}

// isDenied returns true when addr falls inside any deny prefix.
func (f *JwksFetcher) isDenied(addr netip.Addr) bool {
	for _, p := range f.denied {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseDeniedRanges parses CIDR strings into netip.Prefix values, with
// the dev-loopback override applied.
func parseDeniedRanges(ranges []string, allowLoopbackInDev bool) ([]netip.Prefix, error) {
	loopbackV4 := netip.MustParsePrefix("127.0.0.0/8")
	loopbackV6 := netip.MustParsePrefix("::1/128")

	out := make([]netip.Prefix, 0, len(ranges))
	for _, raw := range ranges {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("dcr/jwks: invalid CIDR %q: %w", raw, err)
		}
		if allowLoopbackInDev && (p == loopbackV4 || p == loopbackV6) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func readCappedBody(r io.Reader) ([]byte, error) {
	// MaxBodyBytes+1 so we can detect overflow. If we read MaxBodyBytes+1
	// the body is too large.
	limited := io.LimitReader(r, MaxBodyBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("dcr/jwks: read body: %w", err)
	}
	if len(buf) > MaxBodyBytes {
		return nil, fmt.Errorf("dcr/jwks: response body exceeds %d bytes", MaxBodyBytes)
	}
	return buf, nil
}

func resolveRedirect(currentURL, location string) (string, error) {
	cur, err := url.Parse(currentURL)
	if err != nil {
		return "", err
	}
	next, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return cur.ResolveReference(next).String(), nil
}

// defaultResolve looks the host up via the system resolver and returns
// netip.Addr values (so we can check against netip.Prefix deny rules
// without re-parsing).
func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	// If host is already a literal IP, return it directly.
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	r := net.DefaultResolver
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// defaultDial is the production dialer (a *net.Dialer with sane defaults).
func defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return d.DialContext(ctx, network, addr)
}
