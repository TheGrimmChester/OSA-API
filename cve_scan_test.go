package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostJSONRetriesLikeGet(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if hits == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	c, _ := newTestCVEClient(srv.URL, newCVEBudget(10))
	body, err := c.postJSON(context.Background(), srv.URL+"/v1/query", []byte(`{"version":"1.0.0"}`), 0)
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if !strings.Contains(string(body), "vulns") {
		t.Fatalf("body=%q", body)
	}
	if hits != 2 {
		t.Fatalf("hits=%d want 2", hits)
	}
}

func TestQueryOSVUsesCache(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-test","summary":"demo"}]}`))
	}))
	defer srv.Close()

	cveHTTPInst = newCVEHTTPClient(5e9, newCVEBudget(10))
	cveHTTPInst.allowHost(srv.URL)
	osvAPIBase = srv.URL
	cveCacheInst = newLayeredCache(newMemCache(100), nil)
	cveFlight = newSingleflight()

	ctx := context.Background()
	v1, err := queryOSV(ctx, "npm", "left-pad", "1.0.0")
	if err != nil || len(v1) != 1 {
		t.Fatalf("first query: err=%v vulns=%d", err, len(v1))
	}
	v2, err := queryOSV(ctx, "npm", "left-pad", "1.0.0")
	if err != nil || len(v2) != 1 {
		t.Fatalf("second query: err=%v vulns=%d", err, len(v2))
	}
	if hits != 1 {
		t.Fatalf("server hits=%d want 1 (cached)", hits)
	}
}

func TestScanCVEFromLockfileWithFakeOSV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Package.Name == "lodash" && req.Version == "4.17.20" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-demo","summary":"proto pollution","aliases":["CVE-2021-0001"],"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	cveHTTPInst = newCVEHTTPClient(5e9, newCVEBudget(50))
	cveHTTPInst.allowHost(srv.URL)
	osvAPIBase = srv.URL
	cveCacheInst = newLayeredCache(newMemCache(100), nil)
	cveFlight = newSingleflight()
	writer = nil

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
	  "lockfileVersion": 3,
	  "packages": {"node_modules/lodash": {"version": "4.17.20"}}
	}`), 0o644)

	n, err := scanCVE("srun-test", "org", "proj", "svc", dir, "main", 0, "sha")
	if err != nil {
		t.Fatalf("scanCVE: %v", err)
	}
	if n != 1 {
		t.Fatalf("findings=%d want 1", n)
	}
}
