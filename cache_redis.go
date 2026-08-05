package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A minimal RESP2 Redis client: GET, SET…EX, PING. Nothing else.
//
// Hand-rolled rather than go-redis, and the reason is not line count — it is
// owning the failure path. This repo has no direct third-party dependencies, and
// "the cache must never fail or slow a scan" means fighting a library's own dial,
// retry and pool defaults on every call while Redis is down. Three commands with
// explicit timeouts and an explicit breaker is less code than the configuration
// needed to make a general-purpose client behave this way.
//
// Scope limit, deliberately: RESP2 only. No cluster, no pipelining, no pub/sub.
// If any of those is ever needed, that is the moment to reconsider the dependency —
// not now.

const (
	redisDialTimeout = 300 * time.Millisecond
	redisIOTimeout   = 500 * time.Millisecond

	// A slow cache should be skipped, not waited on. These are deliberately
	// shorter than any sane request timeout: waiting 2s for a cache to answer
	// costs more than the lookup it was meant to save.

	redisBreakerThreshold = 3
	redisBreakerCooldown  = 30 * time.Second
)

type redisCache struct {
	addr     string
	username string
	password string
	db       int
	useTLS   bool
	prefix   string

	mu           sync.Mutex
	failures     int
	openUntil    time.Time
	breakerOpen  bool
	errors       int64
	lastLoggedAt time.Time

	// now is injectable for tests.
	now func() time.Time
}

// parseRedisURL accepts redis://[user:pass@]host:port[/db] and rediss:// for TLS.
func parseRedisURL(raw string) (*redisCache, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil // not configured: memory-only, which is a supported mode
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "redis", "rediss":
	default:
		return nil, fmt.Errorf("unsupported REDIS_URL scheme %q (want redis or rediss)", u.Scheme)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":6379"
	}
	c := &redisCache{
		addr:   host,
		useTLS: strings.EqualFold(u.Scheme, "rediss"),
	}
	if u.User != nil {
		c.username = u.User.Username()
		c.password, _ = u.User.Password()
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid REDIS_URL database %q", p)
		}
		c.db = n
	}
	return c, nil
}

func (c *redisCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// available reports whether the breaker permits a call, closing it when the
// cooldown has elapsed.
func (c *redisCache) available() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.breakerOpen {
		return true
	}
	if c.clock().After(c.openUntil) {
		c.breakerOpen = false
		c.failures = 0
		// Logged once, on the transition. A 2000-package scan must not emit 2000
		// log lines about a cache it is not using.
		log.Printf("[INFO] cve cache: redis breaker closed, resuming")
		return true
	}
	return false
}

func (c *redisCache) recordFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors++
	c.failures++
	if c.failures >= redisBreakerThreshold && !c.breakerOpen {
		c.breakerOpen = true
		c.openUntil = c.clock().Add(redisBreakerCooldown)
		log.Printf("[WARN] cve cache: redis breaker OPEN for %s after %d consecutive failures (%v); "+
			"continuing on the in-process cache", redisBreakerCooldown, c.failures, err)
	}
}

func (c *redisCache) recordSuccess() {
	c.mu.Lock()
	c.failures = 0
	c.mu.Unlock()
}

func (c *redisCache) errorCount() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.errors
}

func (c *redisCache) breakerState() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.breakerOpen {
		return "open"
	}
	return "closed"
}

// get returns the value, or false for a miss, an error, or an open breaker — the
// caller cannot tell them apart, which is the point.
func (c *redisCache) get(ctx context.Context, key string) ([]byte, bool) {
	if c == nil || !c.available() {
		return nil, false
	}
	conn, err := c.dial(ctx)
	if err != nil {
		c.recordFailure(err)
		return nil, false
	}
	defer conn.Close()
	val, err := conn.cmdBulk("GET", key)
	if err != nil {
		c.recordFailure(err)
		return nil, false
	}
	c.recordSuccess()
	if val == nil {
		return nil, false
	}
	return val, true
}

func (c *redisCache) set(ctx context.Context, key string, val []byte, ttl time.Duration) {
	if c == nil || !c.available() || ttl <= 0 {
		return
	}
	conn, err := c.dial(ctx)
	if err != nil {
		c.recordFailure(err)
		return
	}
	defer conn.Close()
	// EX takes whole seconds; anything under a second is not worth a round trip.
	secs := int(ttl / time.Second)
	if secs < 1 {
		secs = 1
	}
	if _, err := conn.cmdBulk("SET", key, string(val), "EX", strconv.Itoa(secs)); err != nil {
		c.recordFailure(err)
		return
	}
	c.recordSuccess()
}

// ping is used once at boot to report the backend honestly, and by /status behind
// its own cache floor. Never on the scan path.
func (c *redisCache) ping(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("redis not configured")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.cmdBulk("PING")
	return err
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

// A connection per operation rather than a pool.
//
// Deliberate: the operations are single round trips at ~1 per package, the dial is
// bounded at 300ms, and a pool would need its own health tracking that duplicates
// the breaker above. If profiling ever shows the dial dominating, a pool is the
// change to make — with the breaker kept as-is.
type redisConn struct {
	c  net.Conn
	br *bufio.Reader
}

func (c *redisCache) dial(ctx context.Context) (*redisConn, error) {
	d := net.Dialer{Timeout: redisDialTimeout}
	var conn net.Conn
	var err error
	if c.useTLS {
		conn, err = tls.DialWithDialer(&d, "tcp", c.addr, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", c.addr)
	}
	if err != nil {
		return nil, err
	}
	rc := &redisConn{c: conn, br: bufio.NewReader(conn)}
	if c.password != "" {
		args := []string{"AUTH"}
		if c.username != "" {
			args = append(args, c.username)
		}
		args = append(args, c.password)
		if _, err := rc.cmdBulk(args[0], args[1:]...); err != nil {
			rc.Close()
			return nil, fmt.Errorf("redis auth: %w", err)
		}
	}
	if c.db > 0 {
		if _, err := rc.cmdBulk("SELECT", strconv.Itoa(c.db)); err != nil {
			rc.Close()
			return nil, fmt.Errorf("redis select: %w", err)
		}
	}
	return rc, nil
}

func (rc *redisConn) Close() { _ = rc.c.Close() }

// cmdBulk writes a RESP2 array command and reads one reply.
//
// Returns (nil, nil) for a null bulk string — Redis's "key does not exist" — which
// is distinct from (empty slice, nil) for a key holding an empty value.
func (rc *redisConn) cmdBulk(name string, args ...string) ([]byte, error) {
	_ = rc.c.SetDeadline(time.Now().Add(redisIOTimeout))

	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args)+1)
	fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(name), name)
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := rc.c.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return rc.readReply()
}

func (rc *redisConn) readReply() ([]byte, error) {
	line, err := rc.br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("empty redis reply")
	}
	switch line[0] {
	case '+': // simple string — OK, PONG
		return []byte(line[1:]), nil
	case '-': // error
		return nil, fmt.Errorf("redis: %s", line[1:])
	case ':': // integer
		return []byte(line[1:]), nil
	case '$': // bulk string
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("bad bulk length %q", line[1:])
		}
		if n < 0 {
			return nil, nil // null bulk: key does not exist
		}
		// Bound the read. A cache reply is a small projection; a multi-megabyte one
		// means something is wrong, and reading it would defeat the point of the
		// short IO timeout above.
		if n > redisMaxReply {
			return nil, fmt.Errorf("redis reply too large: %d bytes", n)
		}
		buf := make([]byte, n+2) // value + CRLF
		if _, err := ioReadFull(rc.br, buf); err != nil {
			return nil, err
		}
		return buf[:n], nil
	case '*':
		// No command here returns an array. Failing loudly beats silently
		// mis-parsing if one is ever added.
		return nil, fmt.Errorf("unexpected array reply")
	default:
		return nil, fmt.Errorf("unexpected redis reply type %q", line[0])
	}
}

const redisMaxReply = 4 << 20 // 4 MiB

// ioReadFull is io.ReadFull, spelled out to avoid importing io purely for it in a
// file that otherwise deals only in net and bufio.
func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := r.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
