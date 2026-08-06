package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Outbound HTTP for the CVE sources: one client, a per-host token bucket, bounded
// retries, and a hard request budget.
//
// This does NOT reuse OPL-API/harden.go's pinned dialer. That exists to stop SSRF
// against *user-supplied* URLs, and its `Proxy: nil` would break the egress-proxy
// story. Our base URLs are configuration constants. What is worth borrowing from it
// is the redirect policy: these APIs should not redirect, and following one to an
// arbitrary host reintroduces exactly the surface that argument dismissed.

const cveUserAgent = "osa-api-cve/1"

// Body caps. cve.report's Log4Shell response is 196 KB, so its ceiling is higher —
// but every response is still bounded, because an unbounded read is how one bad
// upstream turns into an OOM.
const (
	cveBodyLimitDefault = 512 << 10 // 512 KiB
	cveBodyLimitLarge   = 1 << 20   // 1 MiB, for cve.report
)

// retryAfterMax bounds a server-supplied delay.
//
// The single most important constant in this file. Unclamped, one buggy
// `Retry-After: 86400` stalls an entire scan for a day — and the header is
// attacker-influenced in the sense that we do not control these servers.
const retryAfterMax = 30 * time.Second

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

// cveBudget caps outbound requests for one scan.
//
// An explicit struct threaded through calls rather than a context value: a ctx
// value is opaque, untyped and untestable, and this is a number an operator tunes
// and a test asserts on.
type cveBudget struct {
	mu    sync.Mutex
	max   int
	spent int
}

func newCVEBudget(max int) *cveBudget {
	if max <= 0 {
		max = 600
	}
	return &cveBudget{max: max}
}

// take reserves one request. False means the budget is exhausted — which is NOT an
// error: the caller keeps every match already obtained and reports
// budget_exhausted in the run summary. A partial CVE scan beats a failed one.
func (b *cveBudget) take() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.spent >= b.max {
		return false
	}
	b.spent++
	return true
}

func (b *cveBudget) used() (spent, max int) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spent, b.max
}

func (b *cveBudget) exhausted() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spent >= b.max
}

// errBudgetExhausted is distinguishable so a caller can report it as a partial
// result rather than a failure.
var errBudgetExhausted = fmt.Errorf("cve request budget exhausted")

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

// tokenBucket is a lazily-refilled rate limiter, one per host.
//
// Lazy refill from elapsed time rather than a background ticker: a goroutine per
// host leaks in tests and outlives the scan that created it.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	perSec   float64
	lastFill time.Time

	now   func() time.Time
	sleep func(time.Duration)
}

func newTokenBucket(perSec, burst float64) *tokenBucket {
	if perSec <= 0 {
		perSec = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{tokens: burst, max: burst, perSec: perSec}
}

func (b *tokenBucket) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

func (b *tokenBucket) nap(d time.Duration) {
	if b.sleep != nil {
		b.sleep(d)
		return
	}
	time.Sleep(d)
}

// wait blocks until a token is available, or the context ends.
//
// The ordering here is the subtle part: the token is deducted UNDER THE LOCK, the
// lock is released, and only then does the caller sleep. Decrementing after the
// sleep would let N concurrent waiters all observe the same token and burst
// straight through the limit — which against a nonprofit CERT is how the product
// gets banned.
func (b *tokenBucket) wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := b.clock()
		if !b.lastFill.IsZero() {
			if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
				b.tokens += elapsed * b.perSec
				if b.tokens > b.max {
					b.tokens = b.max
				}
			}
		}
		b.lastFill = now
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		// How long until one token exists.
		need := (1 - b.tokens) / b.perSec
		b.mu.Unlock()

		d := time.Duration(need * float64(time.Second))
		if d < time.Millisecond {
			d = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		b.nap(d)
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// ---------------------------------------------------------------------------
// Singleflight
// ---------------------------------------------------------------------------

type flightResult struct {
	val []byte
	err error
}

type flight struct {
	done chan struct{}
	res  flightResult
}

// singleflight collapses concurrent identical fetches into one.
type singleflight struct {
	mu sync.Mutex
	m  map[string]*flight
}

func newSingleflight() *singleflight { return &singleflight{m: map[string]*flight{}} }

// do runs fn once per key for all concurrent callers.
//
// Two details are load-bearing. The map entry is deleted BEFORE the result is
// returned, so a later caller starts a fresh flight rather than joining a finished
// one. And fn runs under a recover(): one panicking fetch would otherwise leave
// `done` unclosed and deadlock every waiter on that key forever.
func (s *singleflight) do(key string, fn func() ([]byte, error)) ([]byte, error) {
	s.mu.Lock()
	if f, ok := s.m[key]; ok {
		s.mu.Unlock()
		<-f.done
		return f.res.val, f.res.err
	}
	f := &flight{done: make(chan struct{})}
	s.m[key] = f
	s.mu.Unlock()

	func() {
		defer func() {
			if r := recover(); r != nil {
				f.res = flightResult{err: fmt.Errorf("panic in cve fetch: %v", r)}
			}
			s.mu.Lock()
			delete(s.m, key)
			s.mu.Unlock()
			close(f.done)
		}()
		v, err := fn()
		f.res = flightResult{val: v, err: err}
	}()
	return f.res.val, f.res.err
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type cveHTTPClient struct {
	client  *http.Client
	buckets map[string]*tokenBucket
	// allowed is derived from the env-configured base URLs at boot. It is what
	// makes httptest fakes possible without turning this into an arbitrary-URL
	// fetcher.
	allowed map[string]bool
	mu      sync.Mutex

	budget *cveBudget
	sleep  func(time.Duration)
}

func newCVEHTTPClient(timeout time.Duration, budget *cveBudget) *cveHTTPClient {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &cveHTTPClient{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// From the environment, so the egress proxy story keeps working.
				Proxy:               http.ProxyFromEnvironment,
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 8,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			},
			// These APIs should not redirect. Following one to an arbitrary host
			// would reintroduce the SSRF surface that a fixed base-URL list
			// otherwise removes.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		buckets: map[string]*tokenBucket{},
		allowed: map[string]bool{},
		budget:  budget,
	}
}

// allowHost registers a host derived from a configured base URL.
func (c *cveHTTPClient) allowHost(rawBase string) {
	u, err := url.Parse(strings.TrimSpace(rawBase))
	if err != nil || u.Host == "" {
		return
	}
	c.mu.Lock()
	c.allowed[strings.ToLower(u.Host)] = true
	c.mu.Unlock()
}

func (c *cveHTTPClient) hostAllowed(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allowed[strings.ToLower(host)]
}

// limit registers a rate for a host.
func (c *cveHTTPClient) limit(rawBase string, perSec, burst float64) {
	u, err := url.Parse(strings.TrimSpace(rawBase))
	if err != nil || u.Host == "" {
		return
	}
	b := newTokenBucket(perSec, burst)
	if c.sleep != nil {
		b.sleep = c.sleep
	}
	c.mu.Lock()
	c.buckets[strings.ToLower(u.Host)] = b
	c.mu.Unlock()
}

func (c *cveHTTPClient) bucketFor(host string) *tokenBucket {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buckets[strings.ToLower(host)]
}

func (c *cveHTTPClient) nap(d time.Duration) {
	if c.sleep != nil {
		c.sleep(d)
		return
	}
	time.Sleep(d)
}

// postJSON POSTs JSON to a URL with the same rate limiting, retries and body cap
// as getJSON. Used for OSV /v1/query.
func (c *cveHTTPClient) postJSON(ctx context.Context, rawURL string, payload []byte, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	if !c.hostAllowed(u.Host) {
		return nil, fmt.Errorf("host %q is not a configured CVE source", u.Host)
	}
	if limit <= 0 {
		limit = cveBodyLimitDefault
	}
	if b := c.bucketFor(u.Host); b != nil {
		if err := b.wait(ctx); err != nil {
			return nil, err
		}
	}
	backoff := 100 * time.Millisecond
	const attempts = 3
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if !c.budget.take() {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errBudgetExhausted
		}
		body, retryable, retryAfter, err := c.attemptPost(ctx, rawURL, payload, limit)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable || attempt == attempts {
			return nil, err
		}
		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}
		if dl, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(dl) {
			return nil, fmt.Errorf("%w (retry would exceed the scan deadline)", err)
		}
		c.nap(wait)
		backoff *= 2
	}
	return nil, lastErr
}

func (c *cveHTTPClient) attemptPost(ctx context.Context, rawURL string, payload []byte, limit int64) (body []byte, retryable bool, retryAfter time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(payload)))
	if err != nil {
		return nil, false, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", cveUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, 0, err
		}
		return nil, true, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, 0, nil
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusInternalServerError,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		return nil, true, parseRetryAfter(resp.Header.Get("Retry-After")),
			fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, false, 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}

	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, limit))
	if rerr != nil {
		return nil, true, 0, rerr
	}
	if int64(len(raw)) >= limit {
		return nil, false, 0, fmt.Errorf("response from %s exceeded the %d-byte cap", req.URL.Host, limit)
	}
	return raw, false, 0, nil
}

// getJSON fetches a URL with rate limiting, retries and a body cap.
//
// Returns (nil, nil) for a definitive 404 — the caller negative-caches that. Any
// other failure is an error, and only a definitive 404 is ever cached: a
// 5xx/timeout/breaker-open must not poison results for a day.
func (c *cveHTTPClient) getJSON(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	if !c.hostAllowed(u.Host) {
		// A host not derived from configuration must never be fetched. This is the
		// one place user input could reach an outbound request.
		return nil, fmt.Errorf("host %q is not a configured CVE source", u.Host)
	}
	if limit <= 0 {
		limit = cveBodyLimitDefault
	}

	if b := c.bucketFor(u.Host); b != nil {
		if err := b.wait(ctx); err != nil {
			return nil, err
		}
	}

	backoff := 100 * time.Millisecond
	const attempts = 3
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if !c.budget.take() {
			// Preserve whatever caused the last failure, so a budget exhaustion on
			// a retry does not hide a real error.
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errBudgetExhausted
		}
		body, retryable, retryAfter, err := c.attempt(ctx, rawURL, limit)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable || attempt == attempts {
			return nil, err
		}
		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}
		// Never wait past the caller's deadline: a scan-wide timeout must win over
		// one source's back-pressure.
		if dl, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(dl) {
			return nil, fmt.Errorf("%w (retry would exceed the scan deadline)", err)
		}
		c.nap(wait)
		backoff *= 2
	}
	return nil, lastErr
}

// attempt makes one request. retryable says whether another try could help.
func (c *cveHTTPClient) attempt(ctx context.Context, rawURL string, limit int64) (body []byte, retryable bool, retryAfter time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", cveUserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		// Dial and IO errors are worth another try; a cancelled context is not.
		if ctx.Err() != nil {
			return nil, false, 0, err
		}
		return nil, true, 0, err
	}
	defer func() {
		// Drain before Close so the connection can be reused. clickhouse.go does
		// this; hub_github.go's proxyPeerGET forgets to, which quietly disables
		// keep-alive for every hub call.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// Definitive absence. The ONLY cacheable negative.
		return nil, false, 0, nil
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusInternalServerError,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		return nil, true, parseRetryAfter(resp.Header.Get("Retry-After")),
			fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		// 400/401/403 and friends: retrying sends the same rejected request.
		return nil, false, 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}

	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, limit))
	if rerr != nil {
		return nil, true, 0, rerr
	}
	if int64(len(raw)) >= limit {
		// Truncated JSON would parse into a plausible-looking partial record, so
		// this is an error rather than a best-effort decode.
		return nil, false, 0, fmt.Errorf("response from %s exceeded the %d-byte cap", req.URL.Host, limit)
	}
	return raw, false, 0, nil
}

// parseRetryAfter reads the header and CLAMPS it.
//
// Both forms are accepted: integer seconds, then an HTTP-date. The clamp is the
// point — unclamped, one `Retry-After: 86400` stalls a scan for a day, and these
// are servers we do not control.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return clampRetryAfter(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(v); err == nil {
		return clampRetryAfter(time.Until(t))
	}
	return 0
}

func clampRetryAfter(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > retryAfterMax {
		return retryAfterMax
	}
	return d
}
