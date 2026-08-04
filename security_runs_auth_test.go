package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityRunSubRequiresAuthWhenEnforced(t *testing.T) {
	prevAuth := authEnforced
	prevGate := authGate
	authEnforced = true
	defer func() {
		authEnforced = prevAuth
		authGate = prevGate
	}()

	// Bootstrap a real gate so AuthMiddleware rejects missing tokens.
	initAuthMode()
	if authGate == nil {
		t.Fatal("expected auth gate")
	}

	mux := http.NewServeMux()
	authView := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, AuthMiddleware(h, "viewer"))
	}
	registerSecurityRunsMux(mux, authView, func(string, http.HandlerFunc) {})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/security/runs/srun-test", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated run GET: code=%d body=%s", rr.Code, rr.Body.String())
	}
}
