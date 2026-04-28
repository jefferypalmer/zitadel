package software_statement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// JWKSFetchFailedKey is the i18n key returned when the per-issuer JWKS
// fetch (or rotation refetch) fails. cavekit-software-statement.md R4
// requires the verifier to refuse the JWT — never serve stale keys on
// rotation refetch failure.
const JWKSFetchFailedKey = "Errors.DCR.SoftwareStatement.JWKSFetchFailed"

// jwksFetcher is the subset of internal/api/oidc/dcr.JwksFetcher we
// need. Threaded as an interface so the cache can be unit-tested with
// a stub fetcher (no network).
type jwksFetcher interface {
	Fetch(ctx context.Context, jwksURI string) ([]byte, error)
}

// JWKSCache is the per-issuer (NOT per-URL) cache from
// cavekit-software-statement.md R4. Keyed by issuer string verbatim;
// TTL set from `OIDC.DCR.SoftwareStatement.JWKSCacheTTL`. Cached
// entries return synchronously; misses fetch through the underlying
// SSRF-guarded fetcher.
//
// Discovery: when the trusted-issuer descriptor's JWKSURI is empty,
// the cache fetches `${Issuer}/.well-known/openid-configuration`
// first, reads `jwks_uri` from the JSON, then fetches that URL.
// Discovery and JWKS fetch share the same fetcher so the same SSRF
// rules apply to both legs.
//
// Concurrency: a sync.RWMutex guards the map. Misses do NOT hold the
// write lock during the fetch — we drop to the read lock, fetch, then
// re-acquire the write lock to publish. This means multiple
// goroutines may race and each fetch independently — we accept that
// duplicate work over a sync.Singleflight because the cache is small,
// TTLs are typically 1h, and a single-flight cache adds complexity
// the kit does not require.
// CacheLookupOutcome enumerates the three observable outcomes of a
// per-issuer JWKS cache lookup. Mirrors the label values on
// `zitadel.dcr.software_statement_jwks_cache_hits_total` (T-043).
type CacheLookupOutcome string

const (
	CacheOutcomeHit           CacheLookupOutcome = "hit"
	CacheOutcomeMiss          CacheLookupOutcome = "miss"
	CacheOutcomeRefetchFailed CacheLookupOutcome = "refetch_failed"
)

// CacheLookupRecorder is invoked once per JWKSCache.Get call with the
// issuer and the observed outcome. The metrics layer wires this to
// `zitadel.dcr.software_statement_jwks_cache_hits_total` (cavekit-
// software-statement.md R11 / T-043). Implementations MUST NOT block —
// the call is on the verifier hot path. nil disables recording.
type CacheLookupRecorder func(ctx context.Context, iss string, outcome CacheLookupOutcome)

type JWKSCache struct {
	fetcher jwksFetcher
	ttl     time.Duration

	mu      sync.RWMutex
	entries map[string]*cacheEntry

	// recorder is the optional cache-lookup metric callback (T-043).
	recorder CacheLookupRecorder

	// now is overridable for tests so we don't sleep through TTLs.
	now func() time.Time
}

type cacheEntry struct {
	jwksBytes []byte
	storedAt  time.Time
}

// NewJWKSCache constructs a per-issuer cache. The fetcher is the
// SSRF-guarded fetcher from internal/api/oidc/dcr/jwks_fetcher.go;
// passing it in by interface keeps this package's import graph clean.
// `ttl <= 0` disables the cache entirely (every Get refetches).
func NewJWKSCache(fetcher jwksFetcher, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		fetcher: fetcher,
		ttl:     ttl,
		entries: map[string]*cacheEntry{},
		now:     time.Now,
	}
}

// SetLookupRecorder installs the cache-lookup metric callback (T-043).
// Wiring happens at server bootstrap (cmd/start/start.go) — production
// passes a closure that calls dcr.RecordSoftwareStatementJWKSCacheLookup.
// Tests pass nil to skip metric emission.
func (c *JWKSCache) SetLookupRecorder(rec CacheLookupRecorder) {
	c.recorder = rec
}

// Get returns the JWKS bytes for an issuer. Cached entries return
// synchronously when within TTL. Cache miss / TTL expiry triggers a
// fetch through `fetchJWKS` which honours `descriptor.JWKSURI` (when
// set) or runs OIDC discovery against `${descriptor.Issuer}` (when
// JWKSURI is empty).
//
// On fetch failure (network error, SSRF guard refusal, non-2xx,
// undecodable discovery doc) Get returns nil + a *ParseError keyed
// JWKSFetchFailedKey. cavekit-software-statement.md R4 explicitly:
// MUST NOT serve stale on key-rotation refetch failure — so on refetch
// failure for a previously-cached issuer, we evict the stale entry
// before returning the error.
func (c *JWKSCache) Get(ctx context.Context, descriptor TrustedIssuer) ([]byte, *ParseError) {
	if descriptor.Issuer == "" {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: trusted-issuer descriptor missing Issuer",
			I18nKey:     JWKSFetchFailedKey,
		}
	}

	if c.ttl > 0 {
		c.mu.RLock()
		entry, ok := c.entries[descriptor.Issuer]
		c.mu.RUnlock()
		if ok && c.now().Sub(entry.storedAt) < c.ttl {
			c.recordLookup(ctx, descriptor.Issuer, CacheOutcomeHit)
			return entry.jwksBytes, nil
		}
	}

	bytes, err := c.fetchJWKS(ctx, descriptor)
	if err != nil {
		// Evict any stale entry — kit R4 forbids serving stale on
		// rotation refetch failure. The previously-cached entry's
		// existence determines whether we report `refetch_failed` (we
		// had a working cache for this issuer) versus a bare `miss`
		// followed by a fetch failure (cold lookup).
		c.mu.Lock()
		_, hadStale := c.entries[descriptor.Issuer]
		delete(c.entries, descriptor.Issuer)
		c.mu.Unlock()
		outcome := CacheOutcomeMiss
		if hadStale {
			outcome = CacheOutcomeRefetchFailed
		}
		c.recordLookup(ctx, descriptor.Issuer, outcome)
		return nil, err
	}
	c.mu.Lock()
	c.entries[descriptor.Issuer] = &cacheEntry{
		jwksBytes: bytes,
		storedAt:  c.now(),
	}
	c.mu.Unlock()
	c.recordLookup(ctx, descriptor.Issuer, CacheOutcomeMiss)
	return bytes, nil
}

func (c *JWKSCache) recordLookup(ctx context.Context, iss string, outcome CacheLookupOutcome) {
	if c.recorder != nil {
		c.recorder(ctx, iss, outcome)
	}
}

// Invalidate removes the cached entry for an issuer. Useful when a
// caller learns externally that the issuer rotated keys (we don't
// currently expose this, but the door is open for T-027 to call it
// on a `kid` mismatch followed by a successful refetch).
func (c *JWKSCache) Invalidate(issuer string) {
	c.mu.Lock()
	delete(c.entries, issuer)
	c.mu.Unlock()
}

// fetchJWKS resolves the descriptor's effective JWKS URL (either
// JWKSURI when set, or via OIDC discovery), runs the underlying
// SSRF-guarded fetcher, and returns the raw JSON bytes.
func (c *JWKSCache) fetchJWKS(ctx context.Context, descriptor TrustedIssuer) ([]byte, *ParseError) {
	jwksURL := strings.TrimSpace(descriptor.JWKSURI)
	if jwksURL == "" {
		discoveryURL := strings.TrimRight(descriptor.Issuer, "/") + "/.well-known/openid-configuration"
		discoveryBytes, err := c.fetcher.Fetch(ctx, discoveryURL)
		if err != nil {
			return nil, wrapJWKSFetchError(err, "discovery")
		}
		var discovery struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(discoveryBytes, &discovery); err != nil {
			return nil, &ParseError{
				Code:        "invalid_software_statement",
				Description: "software_statement: issuer discovery document is not valid JSON",
				I18nKey:     JWKSFetchFailedKey,
				Wrapped:     err,
			}
		}
		jwksURL = strings.TrimSpace(discovery.JWKSURI)
		if jwksURL == "" {
			return nil, &ParseError{
				Code:        "invalid_software_statement",
				Description: "software_statement: issuer discovery document missing jwks_uri",
				I18nKey:     JWKSFetchFailedKey,
			}
		}
	}
	bytes, err := c.fetcher.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, wrapJWKSFetchError(err, "jwks")
	}
	if len(bytes) == 0 {
		return nil, &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: empty JWKS response",
			I18nKey:     JWKSFetchFailedKey,
		}
	}
	return bytes, nil
}

func wrapJWKSFetchError(err error, stage string) *ParseError {
	return &ParseError{
		Code:        "invalid_software_statement",
		Description: fmt.Sprintf("software_statement: %s fetch failed", stage),
		I18nKey:     JWKSFetchFailedKey,
		Wrapped:     err,
	}
}

// errors.Is wiring so callers can check for the package-level "fetch
// failed" sentinel without unwrapping ParseError manually.
var ErrJWKSFetchFailed = errors.New("jwks fetch failed")
