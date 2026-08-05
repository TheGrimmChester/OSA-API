package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemCacheExpiresOnRead(t *testing.T) {
	c := newMemCache(100)
	now := time.Now()
	c.now = func() time.Time { return now }

	c.set("k", []byte("v"), time.Minute)
	if v, ok := c.get("k"); !ok || string(v) != "v" {
		t.Fatalf("got %q ok=%v", v, ok)
	}
	// Past the TTL. Expiry happens on read rather than via a sweeper goroutine,
	// which is why no sleep is needed here.
	now = now.Add(2 * time.Minute)
	if _, ok := c.get("k"); ok {
		t.Fatal("expired entry was served")
	}
	if s := c.stats(); s.Entries != 0 {
		t.Fatalf("expired entry not removed: %d entries", s.Entries)
	}
}

func TestMemCacheEvictsAtCapacity(t *testing.T) {
	c := newMemCache(10)
	for i := 0; i < 25; i++ {
		c.set(fmt.Sprintf("k%02d", i), []byte("v"), time.Hour)
	}
	s := c.stats()
	if s.Entries > 10 {
		t.Fatalf("cache grew past its cap: %d entries", s.Entries)
	}
	if s.Evictions == 0 {
		t.Fatal("no evictions recorded — the cap would be silently exceeded")
	}
}

// A zero or negative TTL must not be stored: it would be an entry that is already
// expired, occupying a slot and forcing an eviction on the next insert.
func TestMemCacheRejectsNonPositiveTTL(t *testing.T) {
	c := newMemCache(10)
	c.set("a", []byte("v"), 0)
	c.set("b", []byte("v"), -time.Second)
	if s := c.stats(); s.Entries != 0 {
		t.Fatalf("stored %d entries with a non-positive TTL", s.Entries)
	}
}

// Negative entries are the anti-spam mechanism, so serving one has to be countable:
// on a mostly-clean repository this number should dominate.
func TestNegativeHitsAreCounted(t *testing.T) {
	lc := newLayeredCache(newMemCache(100), nil)
	ctx := context.Background()

	lc.Set(ctx, "src:osv:npm:left-pad:1.0.0", negativeEntry, time.Hour)
	lc.Set(ctx, "src:osv:npm:lodash:4.17.20", []byte(`{"vulns":[{"id":"GHSA-x"}]}`), time.Hour)

	for i := 0; i < 3; i++ {
		if _, ok := lc.Get(ctx, "src:osv:npm:left-pad:1.0.0"); !ok {
			t.Fatal("negative entry not served")
		}
	}
	lc.Get(ctx, "src:osv:npm:lodash:4.17.20")

	if s := lc.Stats(); s.NegativeHits != 3 {
		t.Fatalf("negative_hits=%d, want 3 — this is the anti-spam number, measured", s.NegativeHits)
	}
}

// An empty stored value and a cache miss must stay distinguishable, or negative
// caching silently stops working: an empty []byte round-trips as "no entry".
func TestNegativeEntryIsAMarkerNotAnEmptyValue(t *testing.T) {
	if len(negativeEntry) == 0 {
		t.Fatal("negativeEntry must be a non-empty marker")
	}
	if isNegativeEntry(nil) || isNegativeEntry([]byte("")) {
		t.Fatal("an empty value must not be treated as a negative entry")
	}
	if !isNegativeEntry(negativeEntry) {
		t.Fatal("the marker must be recognised")
	}
}

func TestLayeredBackendNamesWhatIsActuallyInUse(t *testing.T) {
	if got := newLayeredCache(newMemCache(10), nil).Backend(); got != "memory" {
		t.Fatalf("backend=%q want memory", got)
	}
	rc, err := parseRedisURL("redis://127.0.0.1:6379/0")
	if err != nil {
		t.Fatalf("parseRedisURL: %v", err)
	}
	if got := newLayeredCache(newMemCache(10), rc).Backend(); got != "redis+memory" {
		t.Fatalf("backend=%q want redis+memory", got)
	}
}

// The whole posture in one test: with Redis pointed at a closed port the cache must
// return fast misses, never an error, and never a panic. There is no error to
// propagate, so a scan cannot fail because of the cache.
func TestRedisAtAClosedPortDegradesToMisses(t *testing.T) {
	// Port 1 is reliably closed and refuses immediately.
	rc, err := parseRedisURL("redis://127.0.0.1:1/0")
	if err != nil {
		t.Fatalf("parseRedisURL: %v", err)
	}
	lc := newLayeredCache(newMemCache(100), rc)
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 6; i++ {
		if _, ok := lc.Get(ctx, fmt.Sprintf("miss-%d", i)); ok {
			t.Fatal("a closed Redis returned a hit")
		}
		lc.Set(ctx, fmt.Sprintf("miss-%d", i), []byte("v"), time.Minute)
	}
	elapsed := time.Since(start)
	// Six round trips against a refusing port, bounded by a 300ms dial timeout and
	// then short-circuited by the breaker. Generous ceiling, but it would fail
	// outright if the dial were unbounded.
	if elapsed > 5*time.Second {
		t.Fatalf("closed Redis cost %v — a slow cache must be skipped, not waited on", elapsed)
	}
	// L1 still works, which is why "Redis died mid-run" needs no special case.
	if v, ok := lc.Get(ctx, "miss-0"); !ok || string(v) != "v" {
		t.Fatal("L1 stopped working when L2 was unreachable")
	}
	// And the breaker opened rather than retrying forever.
	if s := lc.Stats(); s.Breaker != "open" {
		t.Fatalf("breaker=%q want open after repeated failures", s.Breaker)
	}
}

func TestBreakerOpensOnceAndClosesAfterCooldown(t *testing.T) {
	rc, _ := parseRedisURL("redis://127.0.0.1:1/0")
	now := time.Now()
	rc.now = func() time.Time { return now }

	for i := 0; i < redisBreakerThreshold; i++ {
		rc.recordFailure(fmt.Errorf("dial refused"))
	}
	if rc.breakerState() != "open" {
		t.Fatal("breaker did not open at the threshold")
	}
	if rc.available() {
		t.Fatal("an open breaker must refuse calls")
	}
	now = now.Add(redisBreakerCooldown + time.Second)
	if !rc.available() {
		t.Fatal("breaker did not close after the cooldown")
	}
	if rc.breakerState() != "closed" {
		t.Fatal("breaker state not reset")
	}
}

func TestParseRedisURL(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		addr    string
		db      int
		tls     bool
		user    string
		pass    string
		wantNil bool
		wantErr bool
	}{
		{raw: "", wantNil: true}, // unset is a supported mode, not an error
		{raw: "redis://redis:6379/0", addr: "redis:6379"},
		{raw: "redis://redis", addr: "redis:6379"}, // default port
		{raw: "redis://redis:6379/3", addr: "redis:6379", db: 3},
		{raw: "rediss://redis:6380/1", addr: "redis:6380", db: 1, tls: true},
		{raw: "redis://user:pw@redis:6379", addr: "redis:6379", user: "user", pass: "pw"},
		{raw: "memcached://x:1", wantErr: true},
		{raw: "redis://redis:6379/notanumber", wantErr: true},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseRedisURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if got != nil {
					t.Fatal("an unset REDIS_URL must yield no client, not an error")
				}
				return
			}
			if got.addr != tc.addr || got.db != tc.db || got.useTLS != tc.tls ||
				got.username != tc.user || got.password != tc.pass {
				t.Fatalf("parsed %+v", got)
			}
		})
	}
}

// Singleflight collapses concurrent identical fetches. Two details are
// load-bearing: the map entry is deleted before returning, and fn runs under a
// recover() — one panicking fetch would otherwise leave `done` unclosed and
// deadlock every waiter on that key forever.
func TestSingleflightRunsTheFetchOnce(t *testing.T) {
	sf := newSingleflight()
	var calls int64
	release := make(chan struct{})

	const n = 20
	var wg sync.WaitGroup
	results := make([][]byte, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := sf.do("same-key", func() ([]byte, error) {
				atomic.AddInt64(&calls, 1)
				<-release // hold the flight open so the others pile up
				return []byte("payload"), nil
			})
			if err != nil {
				t.Errorf("do: %v", err)
			}
			results[i] = v
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("fetch ran %d times, want 1", got)
	}
	for i, v := range results {
		if string(v) != "payload" {
			t.Fatalf("waiter %d got %q", i, v)
		}
	}
}

// A panicking fetch must not deadlock the waiters — it must surface as an error to
// all of them, and leave the key usable afterwards.
func TestSingleflightSurvivesAPanickingFetch(t *testing.T) {
	sf := newSingleflight()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := sf.do("boom", func() ([]byte, error) { panic("upstream exploded") })
		if err == nil {
			t.Error("a panicking fetch must surface as an error")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter deadlocked on a panicking fetch")
	}
	// The key is released, so a later caller starts a fresh flight.
	v, err := sf.do("boom", func() ([]byte, error) { return []byte("ok"), nil })
	if err != nil || string(v) != "ok" {
		t.Fatalf("key not released after the panic: v=%q err=%v", v, err)
	}
}

// A finished flight must not be joined: the entry is deleted before the result is
// returned, so a sequential second call re-runs.
func TestSingleflightDoesNotJoinAFinishedFlight(t *testing.T) {
	sf := newSingleflight()
	var calls int64
	fn := func() ([]byte, error) {
		atomic.AddInt64(&calls, 1)
		return []byte("v"), nil
	}
	_, _ = sf.do("k", fn)
	_, _ = sf.do("k", fn)
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("sequential calls ran the fetch %d times, want 2", got)
	}
}
