package main

import (
	"context"
	"sync"
	"time"
)

// The CVE cache: an in-process L1 with an optional Redis L2.
//
// The requirement this serves is anti-spam. Most packages have zero CVEs, and
// "zero" is far more stable than "vulnerable" — so the negative entries are what
// actually stop a CI storm hammering api.osv.dev, cve.report and cve.circl.lu.
// CIRCL in particular is a nonprofit CERT; being rude there is how the whole
// product gets banned.
//
// This follows the posture already set by OPA-Hub/internal/oamdir, whose doc
// comment states that a stale cache is preferred to an error because a brief
// outage should not empty every product's picker. Same rule here, one step
// stronger: a cache failure must not even be *visible* to the caller.

// cacheStats is what /api/security/cve/status reports. Counters only — the status
// endpoint must never probe live, or a dashboard poll becomes an OSV hammer.
type cacheStats struct {
	Hits         int64  `json:"hits"`
	Misses       int64  `json:"misses"`
	NegativeHits int64  `json:"negative_hits"`
	Sets         int64  `json:"sets"`
	Evictions    int64  `json:"evictions"`
	Entries      int    `json:"entries"`
	L2Errors     int64  `json:"l2_errors"`
	Breaker      string `json:"breaker"`
}

// cveCache is deliberately error-free.
//
// Get has no error return, so there is no error for a caller to accidentally
// propagate into a scan. "Redis is down" and "not cached" are the same event from
// the caller's point of view, which is the structural enforcement of "the cache
// must never fail the scan" — a rule that a returned error would leave to the
// discipline of every call site.
type cveCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
	Backend() string
	Stats() cacheStats
}

// ---------------------------------------------------------------------------
// L1: in-process
// ---------------------------------------------------------------------------

type memEntry struct {
	val       []byte
	expiresAt time.Time
}

type memCache struct {
	mu      sync.Mutex
	entries map[string]memEntry
	max     int

	hits, misses, sets, evictions int64

	// now is injectable so TTL expiry is testable without sleeping. Production
	// leaves it nil and reads the wall clock.
	now func() time.Time
}

func newMemCache(max int) *memCache {
	if max <= 0 {
		max = 20000
	}
	return &memCache{entries: make(map[string]memEntry, 256), max: max}
}

func (c *memCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *memCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		c.misses++
		return nil, false
	}
	if c.clock().After(e.expiresAt) {
		// Expired entries are removed on read rather than by a sweeper goroutine:
		// a background sweeper leaks in tests, and the read path is the only place
		// staleness matters.
		delete(c.entries, key)
		c.misses++
		return nil, false
	}
	c.hits++
	return e.val, true
}

func (c *memCache) set(key string, val []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[key] = memEntry{val: val, expiresAt: c.clock().Add(ttl)}
	c.sets++
}

// evictLocked removes one entry, sampling rather than tracking strict LRU.
//
// Redis's own approximated-LRU trick: look at a handful of keys and drop the worst
// of them. Go's map iteration is already randomized, so the sample is free. Strict
// LRU would need per-*read* bookkeeping on the hot path, for a cache where every
// entry expires on its own anyway.
func (c *memCache) evictLocked() {
	const sample = 8
	var worstKey string
	var worstAt time.Time
	seen := 0
	for k, e := range c.entries {
		if seen == 0 || e.expiresAt.Before(worstAt) {
			worstKey, worstAt = k, e.expiresAt
		}
		seen++
		if seen >= sample {
			break
		}
	}
	if worstKey != "" {
		delete(c.entries, worstKey)
		c.evictions++
	}
}

func (c *memCache) stats() cacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cacheStats{
		Hits:      c.hits,
		Misses:    c.misses,
		Sets:      c.sets,
		Evictions: c.evictions,
		Entries:   len(c.entries),
	}
}

// ---------------------------------------------------------------------------
// Layered
// ---------------------------------------------------------------------------

// layeredCache is L1 plus an optional L2. l2 may be nil.
//
// Because L1 is unconditional, "Redis died mid-run" needs no special case at all:
// it degrades to exactly the same path as REDIS_URL being unset. One code path,
// one thing to test.
type layeredCache struct {
	l1 *memCache
	l2 *redisCache // may be nil

	mu           sync.Mutex
	negativeHits int64
}

func newLayeredCache(l1 *memCache, l2 *redisCache) *layeredCache {
	return &layeredCache{l1: l1, l2: l2}
}

func (c *layeredCache) Backend() string {
	if c.l2 != nil {
		return "redis+memory"
	}
	return "memory"
}

func (c *layeredCache) Get(ctx context.Context, key string) ([]byte, bool) {
	if v, ok := c.l1.get(key); ok {
		c.countNegative(v)
		return v, true
	}
	if c.l2 == nil {
		return nil, false
	}
	v, ok := c.l2.get(ctx, key)
	if !ok {
		return nil, false
	}
	// Promote into L1 so a second lookup in the same scan costs nothing. The TTL
	// is not known here — Redis owns the authoritative expiry — so a short local
	// TTL is used: the L2 entry remains the source of truth.
	c.l1.set(key, v, l1PromotionTTL)
	c.countNegative(v)
	return v, true
}

// l1PromotionTTL bounds how long an L2 value is trusted locally. Short, because
// Redis holds the real TTL and a long local copy would outlive an entry another
// replica invalidated.
const l1PromotionTTL = 5 * time.Minute

func (c *layeredCache) Set(ctx context.Context, key string, val []byte, ttl time.Duration) {
	c.l1.set(key, val, ttl)
	if c.l2 != nil {
		c.l2.set(ctx, key, val, ttl)
	}
}

// countNegative tracks how often a cached "this package has no advisories" answer
// is served. That number is the anti-spam requirement, measured: on a mostly-clean
// repository it should dominate.
func (c *layeredCache) countNegative(v []byte) {
	if !isNegativeEntry(v) {
		return
	}
	c.mu.Lock()
	c.negativeHits++
	c.mu.Unlock()
}

func (c *layeredCache) Stats() cacheStats {
	s := c.l1.stats()
	c.mu.Lock()
	s.NegativeHits = c.negativeHits
	c.mu.Unlock()
	if c.l2 != nil {
		s.L2Errors = c.l2.errorCount()
		s.Breaker = c.l2.breakerState()
	} else {
		s.Breaker = "n/a"
	}
	return s
}

// negativeEntry is the cached form of a definitive "nothing found".
//
// Stored as a marker rather than as an empty body so a genuine empty response and
// a cache miss stay distinguishable — an empty []byte would round-trip as "no
// entry" and defeat the negative caching this whole file exists for.
var negativeEntry = []byte(`{"absent":true}`)

func isNegativeEntry(v []byte) bool {
	return len(v) == len(negativeEntry) && string(v) == string(negativeEntry)
}
