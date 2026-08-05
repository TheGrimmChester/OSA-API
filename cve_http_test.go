package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestCVEClient wires a client against an httptest server, with sleeps recorded
// rather than performed so retry timing is asserted without waiting.
func newTestCVEClient(base string, budget *cveBudget) (*cveHTTPClient, *[]time.Duration) {
	var slept []time.Duration
	c := newCVEHTTPClient(5*time.Second, budget)
	c.sleep = func(d time.Duration) { slept = append(slept, d) }
	c.allowHost(base)
	return c, &slept
}

// A host that did not come from a configured base URL must never be fetched. This
// is the only place user input could reach an outbound request, and it is what makes
// httptest fakes possible without turning this into an arbitrary-URL fetcher.
func TestUnconfiguredHostIsRefused(t *testing.T) {
	c := newCVEHTTPClient(time.Second, newCVEBudget(10))
	c.allowHost("https://api.osv.dev")
	if _, err := c.getJSON(context.Background(), "https://evil.example/v1/query", 0); err == nil {
		t.Fatal("an unconfigured host was fetched")
	}
	// And the configured one is allowed.
	if !c.hostAllowed("api.osv.dev") {
		t.Fatal("the configured host is not allowed")
	}
}

func TestRetriesOn429AndSucceeds(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, slept := newTestCVEClient(srv.URL, newCVEBudget(10))
	body, err := c.getJSON(context.Background(), srv.URL+"/v1/query", 0)
	if err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body=%q", body)
	}
	if atomic.LoadInt64(&hits) != 2 {
		t.Fatalf("made %d requests, want 2", hits)
	}
	// The server-supplied 1s was honoured in preference to the 100ms backoff.
	if len(*slept) != 1 || (*slept)[0] != time.Second {
		t.Fatalf("slept %v, want one 1s wait from Retry-After", *slept)
	}
}

// THE most important assertion in this file. Unclamped, one buggy
// `Retry-After: 86400` stalls an entire scan for a day — and these are servers we
// do not control.
func TestRetryAfterIsClamped(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "86400") // one day
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, slept := newTestCVEClient(srv.URL, newCVEBudget(10))
	start := time.Now()
	if _, err := c.getJSON(context.Background(), srv.URL+"/x", 0); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	// Sleeps are recorded, not performed, so the wall clock proves nothing was
	// actually waited on — and the recorded value proves the clamp.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v — a Retry-After of a day was waited on", elapsed)
	}
	if len(*slept) != 1 {
		t.Fatalf("slept %v", *slept)
	}
	if (*slept)[0] != retryAfterMax {
		t.Fatalf("waited %v, want it clamped to %v", (*slept)[0], retryAfterMax)
	}
}

func TestParseRetryAfterForms(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{raw: "", want: 0},
		{raw: "1", want: time.Second},
		{raw: "30", want: 30 * time.Second},
		{raw: "86400", want: retryAfterMax}, // clamped
		{raw: "-5", want: 0},                // a negative delay is no delay
		{raw: "garbage", want: 0},
		// An HTTP-date in the past yields no delay rather than a negative one.
		{raw: "Mon, 02 Jan 2006 15:04:05 GMT", want: 0},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if got := parseRetryAfter(tc.raw); got != tc.want {
				t.Fatalf("parseRetryAfter(%q)=%v want %v", tc.raw, got, tc.want)
			}
		})
	}
	// A far-future HTTP-date is clamped too, not just integer seconds.
	future := time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got != retryAfterMax {
		t.Fatalf("HTTP-date clamp: got %v want %v", got, retryAfterMax)
	}
}

// A 404 is the ONLY cacheable negative, and it must be fetched once — retrying a
// definitive absence wastes budget against a nonprofit CERT.
func TestNotFoundIsFetchedOnceAndReturnsNoBody(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, _ := newTestCVEClient(srv.URL, newCVEBudget(10))
	body, err := c.getJSON(context.Background(), srv.URL+"/api/cve/CVE-1999-0001.json", 0)
	if err != nil {
		t.Fatalf("a 404 must not be an error: %v", err)
	}
	if body != nil {
		t.Fatalf("a 404 must yield no body, got %q", body)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("made %d requests for a 404, want 1", hits)
	}
}

// 400/403 are not retried either: the same rejected request would be sent again.
func TestClientErrorsAreNotRetried(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var hits int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&hits, 1)
				w.WriteHeader(status)
			}))
			defer srv.Close()
			c, _ := newTestCVEClient(srv.URL, newCVEBudget(10))
			if _, err := c.getJSON(context.Background(), srv.URL+"/x", 0); err == nil {
				t.Fatalf("HTTP %d should be an error", status)
			}
			if atomic.LoadInt64(&hits) != 1 {
				t.Fatalf("HTTP %d was retried %d times", status, hits)
			}
		})
	}
}

// A truncated body would decode into a plausible-looking partial record, so hitting
// the cap is an error rather than a best-effort parse.
func TestOverCapBodyIsATruncationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
	}))
	defer srv.Close()

	c, _ := newTestCVEClient(srv.URL, newCVEBudget(10))
	_, err := c.getJSON(context.Background(), srv.URL+"/big", 1024)
	if err == nil {
		t.Fatal("an over-cap body must be an error, not a partial parse")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("error does not mention the cap: %v", err)
	}
}

// The budget is a hard stop, and exhausting it is NOT an error condition for the
// scan: the caller keeps what it has and reports budget_exhausted.
func TestBudgetStopsFurtherRequests(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	budget := newCVEBudget(2)
	c, _ := newTestCVEClient(srv.URL, budget)
	for i := 0; i < 2; i++ {
		if _, err := c.getJSON(context.Background(), srv.URL+"/x", 0); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, err := c.getJSON(context.Background(), srv.URL+"/x", 0); err == nil {
		t.Fatal("the third request should have been refused")
	}
	if atomic.LoadInt64(&hits) != 2 {
		t.Fatalf("server saw %d requests, want 2", hits)
	}
	if !budget.exhausted() {
		t.Fatal("budget should report exhausted")
	}
	spent, max := budget.used()
	if spent != 2 || max != 2 {
		t.Fatalf("used=%d/%d", spent, max)
	}
}

func TestBudgetDefaultsAndNilSafety(t *testing.T) {
	// A nil budget means unbounded — used by callers that impose their own cap.
	var nilBudget *cveBudget
	if !nilBudget.take() {
		t.Fatal("a nil budget must allow the request")
	}
	if nilBudget.exhausted() {
		t.Fatal("a nil budget is never exhausted")
	}
	if b := newCVEBudget(0); b.max != 600 {
		t.Fatalf("default max=%d want 600", b.max)
	}
	if b := newCVEBudget(-5); b.max != 600 {
		t.Fatalf("negative max=%d want the default", b.max)
	}
}

// The token is deducted UNDER THE LOCK, before any sleep. Deducting after the sleep
// would let N concurrent waiters observe the same token and burst straight through
// the limit — against a nonprofit CERT, that is how the product gets banned.
func TestTokenBucketDeductsBeforeSleeping(t *testing.T) {
	b := newTokenBucket(1, 1) // 1/s, burst 1
	now := time.Now()
	b.now = func() time.Time { return now }
	var slept []time.Duration
	b.sleep = func(d time.Duration) {
		slept = append(slept, d)
		now = now.Add(d) // the sleep advances the clock, refilling the bucket
	}
	ctx := context.Background()

	// The burst token is available immediately.
	if err := b.wait(ctx); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	if len(slept) != 0 {
		t.Fatalf("first call slept %v — the burst token should be free", slept)
	}
	// The second must wait roughly a second.
	if err := b.wait(ctx); err != nil {
		t.Fatalf("second wait: %v", err)
	}
	if len(slept) == 0 {
		t.Fatal("second call did not wait — the rate limit is not being applied")
	}
	total := time.Duration(0)
	for _, d := range slept {
		total += d
	}
	if total < 900*time.Millisecond {
		t.Fatalf("waited only %v for a 1/s limit", total)
	}
}

func TestTokenBucketRespectsContextCancellation(t *testing.T) {
	b := newTokenBucket(1, 1)
	b.sleep = func(time.Duration) {} // do not actually wait
	ctx, cancel := context.WithCancel(context.Background())

	if err := b.wait(ctx); err != nil { // consumes the burst token
		t.Fatalf("first wait: %v", err)
	}
	cancel()
	if err := b.wait(ctx); err == nil {
		t.Fatal("a cancelled context must stop the wait — a scan-wide timeout has to win")
	}
}

// A retry must never push past the caller's deadline: one source's back-pressure
// cannot outlive the scan.
func TestRetryDoesNotExceedTheDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "25")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, slept := newTestCVEClient(srv.URL, newCVEBudget(10))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := c.getJSON(ctx, srv.URL+"/x", 0); err == nil {
		t.Fatal("expected an error")
	}
	if len(*slept) != 0 {
		t.Fatalf("slept %v despite the retry exceeding the deadline", *slept)
	}
}
