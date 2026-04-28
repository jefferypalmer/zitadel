package software_statement

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubFetcher struct {
	responses map[string][]byte
	errs      map[string]error
	calls     map[string]int
}

func newStubFetcher() *stubFetcher {
	return &stubFetcher{
		responses: map[string][]byte{},
		errs:      map[string]error{},
		calls:     map[string]int{},
	}
}

func (s *stubFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	s.calls[url]++
	if e, ok := s.errs[url]; ok {
		return nil, e
	}
	return s.responses[url], nil
}

func TestJWKSCache_DirectJWKSURI_Cached(t *testing.T) {
	f := newStubFetcher()
	f.responses["https://issuer.example/jwks"] = []byte(`{"keys":[]}`)
	c := NewJWKSCache(f, 1*time.Hour)
	c.now = func() time.Time { return time.Unix(0, 0) }

	desc := TrustedIssuer{Issuer: "https://issuer.example", JWKSURI: "https://issuer.example/jwks"}
	for i := 0; i < 3; i++ {
		bytes, err := c.Get(context.Background(), desc)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if string(bytes) != `{"keys":[]}` {
			t.Errorf("iter %d: bytes = %s", i, bytes)
		}
	}
	if got := f.calls["https://issuer.example/jwks"]; got != 1 {
		t.Errorf("fetcher called %d times — expected 1 (cache hit)", got)
	}
}

func TestJWKSCache_TTLExpiryRefetches(t *testing.T) {
	f := newStubFetcher()
	f.responses["https://issuer.example/jwks"] = []byte(`{"keys":[1]}`)
	c := NewJWKSCache(f, 100*time.Millisecond)
	clock := time.Unix(0, 0)
	c.now = func() time.Time { return clock }

	desc := TrustedIssuer{Issuer: "https://issuer.example", JWKSURI: "https://issuer.example/jwks"}
	if _, err := c.Get(context.Background(), desc); err != nil {
		t.Fatalf("first get: %v", err)
	}
	clock = clock.Add(200 * time.Millisecond)
	f.responses["https://issuer.example/jwks"] = []byte(`{"keys":[2]}`)
	bytes, err := c.Get(context.Background(), desc)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if string(bytes) != `{"keys":[2]}` {
		t.Errorf("expected refreshed bytes, got %s", bytes)
	}
}

func TestJWKSCache_DiscoveryWhenJWKSURIEmpty(t *testing.T) {
	f := newStubFetcher()
	f.responses["https://issuer.example/.well-known/openid-configuration"] = []byte(
		`{"jwks_uri":"https://issuer.example/keys.json"}`)
	f.responses["https://issuer.example/keys.json"] = []byte(`{"keys":[]}`)

	c := NewJWKSCache(f, 1*time.Hour)
	desc := TrustedIssuer{Issuer: "https://issuer.example"}
	bytes, err := c.Get(context.Background(), desc)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if string(bytes) != `{"keys":[]}` {
		t.Errorf("bytes = %s", bytes)
	}
	if f.calls["https://issuer.example/.well-known/openid-configuration"] != 1 {
		t.Errorf("discovery not called once")
	}
}

func TestJWKSCache_DiscoveryFailureFails(t *testing.T) {
	f := newStubFetcher()
	f.errs["https://issuer.example/.well-known/openid-configuration"] = errors.New("network down")
	c := NewJWKSCache(f, 1*time.Hour)
	_, err := c.Get(context.Background(), TrustedIssuer{Issuer: "https://issuer.example"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.I18nKey != JWKSFetchFailedKey {
		t.Errorf("I18nKey = %q", err.I18nKey)
	}
}

func TestJWKSCache_DiscoveryMissingJWKSURIFails(t *testing.T) {
	f := newStubFetcher()
	f.responses["https://issuer.example/.well-known/openid-configuration"] = []byte(`{}`)
	c := NewJWKSCache(f, 1*time.Hour)
	_, err := c.Get(context.Background(), TrustedIssuer{Issuer: "https://issuer.example"})
	if err == nil || err.I18nKey != JWKSFetchFailedKey {
		t.Fatalf("want JWKSFetchFailed, got %+v", err)
	}
}

func TestJWKSCache_RefetchFailureEvictsStaleEntry(t *testing.T) {
	f := newStubFetcher()
	f.responses["https://issuer.example/jwks"] = []byte(`{"keys":[1]}`)
	c := NewJWKSCache(f, 100*time.Millisecond)
	clock := time.Unix(0, 0)
	c.now = func() time.Time { return clock }

	desc := TrustedIssuer{Issuer: "https://issuer.example", JWKSURI: "https://issuer.example/jwks"}
	if _, err := c.Get(context.Background(), desc); err != nil {
		t.Fatalf("first get: %v", err)
	}

	// Force a refetch where the upstream is now broken.
	clock = clock.Add(200 * time.Millisecond)
	f.errs["https://issuer.example/jwks"] = errors.New("rotation in progress")
	delete(f.responses, "https://issuer.example/jwks")

	_, err := c.Get(context.Background(), desc)
	if err == nil {
		t.Fatalf("expected refetch failure to be returned (kit R4: must not serve stale)")
	}

	// Restore upstream — and the next Get must refetch (no stale entry).
	delete(f.errs, "https://issuer.example/jwks")
	f.responses["https://issuer.example/jwks"] = []byte(`{"keys":[2]}`)
	bytes, err := c.Get(context.Background(), desc)
	if err != nil {
		t.Fatalf("recovery get: %v", err)
	}
	if string(bytes) != `{"keys":[2]}` {
		t.Errorf("expected recovered bytes, got %s", bytes)
	}
}

func TestJWKSCache_EmptyIssuerRejected(t *testing.T) {
	f := newStubFetcher()
	c := NewJWKSCache(f, 1*time.Hour)
	_, err := c.Get(context.Background(), TrustedIssuer{Issuer: ""})
	if err == nil || err.I18nKey != JWKSFetchFailedKey {
		t.Fatalf("want JWKSFetchFailed, got %+v", err)
	}
}
