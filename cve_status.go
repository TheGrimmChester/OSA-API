package main

import (
	"context"
	"net/http"
	"time"
)

func handleCVECacheStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cveCacheInst == nil {
		writeJSON(w, map[string]interface{}{"backend": "uninitialized"})
		return
	}
	stats := cveCacheInst.Stats()
	redisOK := false
	if rc := cveCacheInst.Redis(); rc != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		redisOK = rc.Ping(ctx) == nil
		cancel()
	}
	writeJSON(w, map[string]interface{}{
		"backend":       cveCacheInst.Backend(),
		"l1_entries":    stats.Entries,
		"l2_hits":       stats.L2Hits,
		"breaker_state": stats.Breaker,
		"redis_ok":      redisOK,
		"hits":          stats.Hits,
		"negative_hits": stats.NegativeHits,
	})
}
