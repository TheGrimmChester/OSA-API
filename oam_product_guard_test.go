package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequireEnabledOAMProjectSkipsWhenUnset(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "")
	req := httptest.NewRequest(http.MethodPost, "/api/security/runs", nil)
	req.Header.Set("X-Project-ID", "checkout-api")
	if st, msg := requireEnabledOAMProject(req, "osa"); st != 0 || msg != "" {
		t.Fatalf("expected skip, got %d %q", st, msg)
	}
}

func TestRequireEnabledOAMProjectSkipsAll(t *testing.T) {
	t.Setenv("PEER_OAM_URL", "http://oam.invalid")
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Project-ID", "all")
	if st, msg := requireEnabledOAMProject(req, "osa"); st != 0 || msg != "" {
		t.Fatalf("expected skip for all, got %d %q", st, msg)
	}
}

func TestOAMDirectoryHasProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "product=osa") {
			t.Errorf("missing product: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]string{{"id": "web"}, {"id": "api"}},
		})
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ok, err := oamDirectoryHasProject(req.Context(), req, srv.URL, "osa", "web")
	if err != nil || !ok {
		t.Fatalf("want found, got ok=%v err=%v", ok, err)
	}
	ok, err = oamDirectoryHasProject(req.Context(), req, srv.URL, "osa", "missing")
	if err != nil || ok {
		t.Fatalf("want missing, got ok=%v err=%v", ok, err)
	}
}

func TestRequireEnabledOAMProjectRejectsDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]string{{"id": "enabled-only"}},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Project-ID", "disabled-here")
	st, msg := requireEnabledOAMProject(req, "osa")
	if st != 403 || msg == "" {
		t.Fatalf("want 403, got %d %q", st, msg)
	}

	q := url.Values{}
	q.Set("product", "osa")
	if got := oamProjectsTarget(srv.URL, q); !strings.Contains(got, "product=osa") {
		t.Fatalf("target %q", got)
	}
}

func TestResolveSCMFromOAMProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{
				{
					"id":            "checkout",
					"external_key":  "acme/checkout",
					"connector_ids": []string{"conn-a", "conn-b"},
				},
			},
		})
	}))
	defer srv.Close()
	t.Setenv("PEER_OAM_URL", srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Project-ID", "checkout")
	cid, repo, msg, code := resolveSCMFromOAMProject(req, "", "")
	if msg != "" || code != 0 {
		t.Fatalf("unexpected err %d %q", code, msg)
	}
	if cid != "conn-a" || repo != "acme/checkout" {
		t.Fatalf("got %s %s", cid, repo)
	}

	cid, repo, msg, code = resolveSCMFromOAMProject(req, "conn-x", "acme/other")
	if msg != "" || code != 0 || cid != "conn-x" || repo != "acme/other" {
		t.Fatalf("explicit override failed: %s %s %d %q", cid, repo, code, msg)
	}

	reqMiss := httptest.NewRequest(http.MethodPost, "/", nil)
	reqMiss.Header.Set("X-Project-ID", "missing")
	_, _, msg, code = resolveSCMFromOAMProject(reqMiss, "", "")
	if code != 403 || msg == "" {
		t.Fatalf("want 403 for missing project, got %d %q", code, msg)
	}
}
