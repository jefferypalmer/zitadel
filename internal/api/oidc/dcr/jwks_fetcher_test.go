package dcr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultDeniedRanges mirrors cmd/defaults.yaml R1 OIDC.DCR.JwksURI.DisallowedIPRanges.
var defaultDeniedRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// TestParseDeniedRanges_AllowLoopbackInDev pins the dev-override
// behavior from cavekit-security-hardening.md R2: when
// AllowLoopbackInDev=true, 127.0.0.0/8 and ::1/128 are removed from
// the effective deny list (everything else stays).
func TestParseDeniedRanges_AllowLoopbackInDev(t *testing.T) {
	tests := []struct {
		name       string
		dev        bool
		wantHas    []string
		wantMisses []string
	}{
		{
			name:    "production — all denies enforced",
			dev:     false,
			wantHas: []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128", "fe80::/10"},
		},
		{
			name:       "dev — loopback removed, other ranges remain",
			dev:        true,
			wantHas:    []string{"10.0.0.0/8", "169.254.0.0/16", "fc00::/7"},
			wantMisses: []string{"127.0.0.0/8", "::1/128"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDeniedRanges(defaultDeniedRanges, tt.dev)
			require.NoError(t, err)
			gotSet := make(map[string]bool, len(got))
			for _, p := range got {
				gotSet[p.String()] = true
			}
			for _, want := range tt.wantHas {
				assert.True(t, gotSet[want], "expected %s in deny set, got %v", want, gotSet)
			}
			for _, missed := range tt.wantMisses {
				assert.False(t, gotSet[missed], "did NOT expect %s in deny set", missed)
			}
		})
	}
}

func TestParseDeniedRanges_InvalidCIDR(t *testing.T) {
	_, err := parseDeniedRanges([]string{"not-a-cidr"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

// TestJwksFetcher_DenyMatrix exhaustively covers the IP-range deny
// list — RFC 1918, link-local (incl. cloud metadata 169.254.169.254),
// IPv4 loopback, IPv6 ULA, IPv6 link-local, IPv6 loopback. R2
// criterion 7 ("Table-driven unit tests in jwks_fetcher_test.go").
func TestJwksFetcher_DenyMatrix(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		ip      string
		wantErr string
	}{
		{name: "RFC 1918 10.0.0.0/8", host: "internal.example", ip: "10.0.0.42", wantErr: "disallowed address"},
		{name: "RFC 1918 172.16/12", host: "internal.example", ip: "172.20.10.5", wantErr: "disallowed address"},
		{name: "RFC 1918 192.168/16", host: "router.local", ip: "192.168.1.1", wantErr: "disallowed address"},
		{name: "loopback 127.0.0.0/8", host: "rebind.example", ip: "127.0.0.1", wantErr: "disallowed address"},
		{name: "link-local 169.254/16", host: "metadata.example", ip: "169.254.169.254", wantErr: "disallowed address"},
		{name: "IPv6 loopback ::1", host: "v6lo.example", ip: "::1", wantErr: "disallowed address"},
		{name: "IPv6 ULA fc00::/7", host: "ula.example", ip: "fc00::1", wantErr: "disallowed address"},
		{name: "IPv6 link-local fe80::/10", host: "v6ll.example", ip: "fe80::1", wantErr: "disallowed address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewJwksFetcher(JwksFetcherConfig{
				HTTPTimeout:        5 * time.Second,
				DisallowedIPRanges: defaultDeniedRanges,
			})
			require.NoError(t, err)
			f.resolve = stubResolve(tt.host, tt.ip)
			f.dial = panicDial(t)

			_, err = f.Fetch(context.Background(), "https://"+tt.host+"/jwks.json")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestJwksFetcher_AllowLoopbackInDev_LetsLoopbackThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	f, err := NewJwksFetcher(JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		AllowLoopbackInDev: true,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	require.NoError(t, err)
	f.resolve = stubResolve(host, "127.0.0.1")

	body, err := f.Fetch(context.Background(), "http://"+net.JoinHostPort(host, port)+"/jwks.json")
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(body))
}

// TestJwksFetcher_OversizedBody asserts the 1 MiB body cap.
func TestJwksFetcher_OversizedBody(t *testing.T) {
	tooLarge := strings.Repeat("a", MaxBodyBytes+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(tooLarge))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		AllowLoopbackInDev: true,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	f.resolve = stubResolve(host, "127.0.0.1")

	_, err := f.Fetch(context.Background(), "http://"+net.JoinHostPort(host, port)+"/jwks.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

// TestJwksFetcher_RedirectCap_3Hops_OK passes when exactly 3 redirects
// chain to a final 200.
func TestJwksFetcher_RedirectCap_3Hops_OK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", redirectTo("/b"))
	mux.HandleFunc("/b", redirectTo("/c"))
	mux.HandleFunc("/c", redirectTo("/d"))
	mux.HandleFunc("/d", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		AllowLoopbackInDev: true,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	f.resolve = stubResolve(host, "127.0.0.1")

	body, err := f.Fetch(context.Background(), "http://"+net.JoinHostPort(host, port)+"/a")
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(body))
}

// TestJwksFetcher_RedirectCap_4Hops_Refused fails when redirect chain
// exceeds 3 hops.
func TestJwksFetcher_RedirectCap_4Hops_Refused(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", redirectTo("/b"))
	mux.HandleFunc("/b", redirectTo("/c"))
	mux.HandleFunc("/c", redirectTo("/d"))
	mux.HandleFunc("/d", redirectTo("/e"))
	mux.HandleFunc("/e", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		AllowLoopbackInDev: true,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	f.resolve = stubResolve(host, "127.0.0.1")

	_, err := f.Fetch(context.Background(), "http://"+net.JoinHostPort(host, port)+"/a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect cap exceeded")
}

// TestJwksFetcher_RedirectTrap_PrivateIP: server redirects to a
// private-IP host. The fetcher MUST re-validate per hop and refuse.
func TestJwksFetcher_RedirectTrap_PrivateIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://internal.example/jwks.json")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		AllowLoopbackInDev: true,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	// public.example resolves to public, internal.example resolves to
	// private — only the redirect target should trigger the deny.
	f.resolve = func(_ context.Context, h string) ([]netip.Addr, error) {
		switch h {
		case host:
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "internal.example":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
		return nil, errors.New("unexpected host")
	}

	_, err := f.Fetch(context.Background(), "http://"+net.JoinHostPort(host, port)+"/start")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed address")
	assert.Contains(t, err.Error(), "internal.example")
}

// TestJwksFetcher_HappyPath_PublicIP (well, simulated public — we use
// a custom dialer that maps a "public" IP to the loopback server).
func TestJwksFetcher_HappyPath_PublicIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kid":"k1"}]}`))
	}))
	defer srv.Close()
	_, port := splitHostPort(t, srv.URL)

	var dialed atomic.Int32
	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	// public IP — passes the deny check.
	f.resolve = stubResolve("api.example", "203.0.113.10")
	// rewrite the dial to target the loopback test server, since we
	// can't reach 203.0.113.10 from the test process.
	f.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialed.Add(1)
		d := &net.Dialer{Timeout: 1 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}

	body, err := f.Fetch(context.Background(), "http://api.example/jwks.json")
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[{"kid":"k1"}]}`, string(body))
	assert.Equal(t, int32(1), dialed.Load(), "should dial exactly once")
}

// TestJwksFetcher_DNSRebindDefense: the resolver returns a public IP
// once, then a private IP on a hypothetical second call — the fetcher
// MUST resolve only ONCE per hop and pin to the first result. We
// verify by counting resolver calls.
func TestJwksFetcher_DNSRebindDefense_OnlyResolvesOncePerHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	_, port := splitHostPort(t, srv.URL)

	var calls atomic.Int32
	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	f.resolve = func(_ context.Context, _ string) ([]netip.Addr, error) {
		n := calls.Add(1)
		if n == 1 {
			return []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil
		}
		// A second call MUST NOT happen for a single hop. If the
		// fetcher ever calls us twice for the same URL, the rebind
		// defense is broken.
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	f.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 1 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}

	_, err := f.Fetch(context.Background(), "http://api.example/jwks.json")
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "exactly one DNS lookup per hop")
}

// TestJwksFetcher_LiteralIPHostInPrivateRange: when the URL itself
// uses a private IP literal, the fetcher must reject without DNS.
func TestJwksFetcher_LiteralIPHostInPrivateRange(t *testing.T) {
	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        2 * time.Second,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	f.dial = panicDial(t)

	_, err := f.Fetch(context.Background(), "http://169.254.169.254/latest/meta-data/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed address")
}

func TestJwksFetcher_BadScheme(t *testing.T) {
	f := mustFetcher(t, JwksFetcherConfig{HTTPTimeout: 1 * time.Second, DisallowedIPRanges: defaultDeniedRanges})
	_, err := f.Fetch(context.Background(), "file:///etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestJwksFetcher_BodyExactlyAtLimit(t *testing.T) {
	exact := strings.Repeat("b", MaxBodyBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(exact))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	f := mustFetcher(t, JwksFetcherConfig{
		HTTPTimeout:        5 * time.Second,
		AllowLoopbackInDev: true,
		DisallowedIPRanges: defaultDeniedRanges,
	})
	f.resolve = stubResolve(host, "127.0.0.1")

	body, err := f.Fetch(context.Background(), "http://"+net.JoinHostPort(host, port)+"/jwks.json")
	require.NoError(t, err)
	assert.Len(t, body, MaxBodyBytes)
}

// ───── helpers ───────────────────────────────────────────────────────

func mustFetcher(t *testing.T, cfg JwksFetcherConfig) *JwksFetcher {
	t.Helper()
	f, err := NewJwksFetcher(cfg)
	require.NoError(t, err)
	return f
}

func stubResolve(wantHost, asIP string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != wantHost {
			return nil, errors.New("unexpected resolver host: " + host)
		}
		return []netip.Addr{netip.MustParseAddr(asIP)}, nil
	}
}

func panicDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		t.Fatalf("dialer must not be invoked when SSRF gate triggers, got addr %q", addr)
		return nil, errors.New("unreachable")
	}
}

func redirectTo(loc string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}
}

func splitHostPort(t *testing.T, rawURL string) (host, port string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	host = u.Hostname()
	port = u.Port()
	return
}
