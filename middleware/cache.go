package middleware

import (
	"sync"
	"time"
)

// sigEntry stores when a given signature expires from the cache.
type sigEntry struct {
	expiresAt time.Time
}

// sigCache is a concurrency-safe, TTL-based cache used to detect replayed
// X-Launcher-Signature values.  A signature that is already present in the
// cache is treated as a replay attack and rejected without performing expensive
// Ed25519 verification a second time.
type sigCache struct {
	mu      sync.Mutex
	entries map[string]sigEntry
	stopCh  chan struct{}
}

func newSigCache() *sigCache {
	c := &sigCache{
		entries: make(map[string]sigEntry),
		stopCh:  make(chan struct{}),
	}
	go c.gc()
	return c
}

// has reports whether sig is present and still valid in the cache.
func (c *sigCache) has(sig string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[sig]
	if !ok {
		return false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, sig)
		return false
	}
	return true
}

// add inserts sig with an expiry of ttl from now.
func (c *sigCache) add(sig string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[sig] = sigEntry{expiresAt: time.Now().Add(ttl)}
}

// stop shuts down the background GC goroutine.  It is safe to call more than
// once.  After Stop returns the cache can no longer be used.
func (c *sigCache) stop() {
	select {
	case <-c.stopCh:
		// already stopped
	default:
		close(c.stopCh)
	}
}

// gc periodically removes expired entries to prevent unbounded memory growth.
func (c *sigCache) gc() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			c.mu.Lock()
			for k, e := range c.entries {
				if now.After(e.expiresAt) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}
