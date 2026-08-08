package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityReposRoutesGone(t *testing.T) {
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
}
