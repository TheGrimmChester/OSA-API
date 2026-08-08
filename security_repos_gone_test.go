package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSecurityReposRoutesGone(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "registerSecurityReposMux") {
		t.Fatal("main.go still registers registerSecurityReposMux — scoreboard routes must stay unregistered")
	}

	mux := http.NewServeMux()
	authView := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, h)
	}
	authAdmin := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, h)
	}
	// Mirror main registration minus the deleted security repos mux.
	registerSecurityRunsMux(mux, authView, authAdmin)
	registerHubGitHubMux(mux, authView)
	registerAppSecMux(mux, authView, authAdmin)
	registerAppSecDeepMux(mux, authView, authAdmin)
	registerVulnMux(mux, authView, authAdmin)
	registerGateMux(mux, authView, authAdmin)

	for _, path := range []string{
		"/api/security/repos",
		"/api/security/repos/",
		"/api/security/repos/acme/widget",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: want 404, got %d body=%s", path, rr.Code, rr.Body.String())
		}
	}

	// Neighbor route still registered.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/security/profiles", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusNotFound {
		t.Fatal("/api/security/profiles should still be registered")
	}
}
