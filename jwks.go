package jwt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// HTTPDoer is the subset of *http.Client used by JWKSCache to fetch a key set.
// Injecting a custom implementation makes the cache testable without real
// network access.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// JWKSCache fetches a JSON Web Key Set from a URL and caches it, refreshing when
// the cached copy grows older than the configured TTL or when a lookup misses
// (an unknown kid, which typically means the provider rotated keys). It is safe
// for concurrent use.
type JWKSCache struct {
	url        string
	client     HTTPDoer
	ttl        time.Duration
	minRefresh time.Duration
	now        func() time.Time

	mu          sync.RWMutex
	set         *JSONWebKeySet
	fetchedAt   time.Time
	lastAttempt time.Time
}

// JWKSCacheOption configures a JWKSCache.
type JWKSCacheOption func(*JWKSCache)

// WithHTTPClient sets the HTTP client used to fetch the JWKS. The default is
// http.DefaultClient. Pass any HTTPDoer (e.g. a fake) to control fetching in
// tests.
func WithHTTPClient(c HTTPDoer) JWKSCacheOption {
	return func(k *JWKSCache) { k.client = c }
}

// WithRefreshInterval sets how long a fetched key set is considered fresh.
// After this TTL elapses the next lookup triggers a refresh. The default is one
// hour.
func WithRefreshInterval(d time.Duration) JWKSCacheOption {
	return func(k *JWKSCache) { k.ttl = d }
}

// WithMinRefreshInterval rate-limits refreshes triggered by an unknown kid, so
// a burst of tokens with a bogus kid cannot cause a fetch storm. The default is
// one minute.
func WithMinRefreshInterval(d time.Duration) JWKSCacheOption {
	return func(k *JWKSCache) { k.minRefresh = d }
}

// withClock injects a time source for deterministic tests.
func withClock(now func() time.Time) JWKSCacheOption {
	return func(k *JWKSCache) { k.now = now }
}

// NewJWKSCache constructs a cache that fetches the JWKS document at url on
// demand. Construction does not perform any network I/O; the first fetch
// happens on the first Get, KeySet, or Keyfunc lookup.
func NewJWKSCache(url string, opts ...JWKSCacheOption) *JWKSCache {
	k := &JWKSCache{
		url:        url,
		client:     http.DefaultClient,
		ttl:        time.Hour,
		minRefresh: time.Minute,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

// KeySet returns the cached key set, fetching it if the cache is empty or its
// TTL has expired. A refresh failure returns the stale set (if any) alongside
// the error so callers may choose to proceed with previously good keys.
func (k *JWKSCache) KeySet(ctx context.Context) (*JSONWebKeySet, error) {
	k.mu.RLock()
	set, fetchedAt := k.set, k.fetchedAt
	k.mu.RUnlock()

	if set != nil && k.now().Sub(fetchedAt) < k.ttl {
		return set, nil
	}
	if err := k.refresh(ctx); err != nil {
		return set, err // stale set (possibly nil) plus error
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.set, nil
}

// Refresh forces an immediate re-fetch of the JWKS, ignoring the TTL. It is
// useful to warm the cache at startup.
func (k *JWKSCache) Refresh(ctx context.Context) error {
	return k.refresh(ctx)
}

// refresh performs the network fetch and atomically swaps the cached set.
func (k *JWKSCache) refresh(ctx context.Context) error {
	k.mu.Lock()
	k.lastAttempt = k.now()
	k.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrJWKSFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	set, err := ParseJWKSet(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	k.mu.Lock()
	k.set = set
	k.fetchedAt = k.now()
	k.mu.Unlock()
	return nil
}

// Keyfunc returns a Keyfunc backed by the cache. On a kid miss it triggers one
// rate-limited refresh (bounded by WithMinRefreshInterval) before giving up, so
// key rotation is picked up without a fetch storm. The context used for any
// refresh is context.Background; use KeyfuncCtx to supply your own.
func (k *JWKSCache) Keyfunc() Keyfunc {
	return k.KeyfuncCtx(context.Background())
}

// KeyfuncCtx is like Keyfunc but uses ctx for any refresh network calls.
func (k *JWKSCache) KeyfuncCtx(ctx context.Context) Keyfunc {
	return func(token *Token) (any, error) {
		set, err := k.KeySet(ctx)
		if err != nil && set == nil {
			return nil, err
		}
		if set != nil {
			if key, err := set.Keyfunc()(token); err == nil {
				return key, nil
			}
		}
		// Miss: the provider may have rotated keys. Refresh at most once per
		// minRefresh window, then retry the lookup.
		k.mu.RLock()
		canRefresh := k.now().Sub(k.lastAttempt) >= k.minRefresh
		k.mu.RUnlock()
		if canRefresh {
			if err := k.refresh(ctx); err != nil {
				return nil, err
			}
			k.mu.RLock()
			set = k.set
			k.mu.RUnlock()
			if set != nil {
				return set.Keyfunc()(token)
			}
		}
		kid, _ := token.Header["kid"].(string)
		return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
	}
}
