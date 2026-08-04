package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// Peer service JWTs (minted by ora-api with OPEN_SERVICE_JWT_SECRET, aud=osa-api)
// must authenticate on the AppSec control-plane routes ora-api actually calls.
// Regression: these routes were wired user-JWT-only, so every peer call from
// ora-api got 401 "invalid token" and the CI gate failed closed as
// peer_unavailable while reporting 0 findings.

const (
	testUserSecret    = "test-user-jwt-secret-at-least-32-bytes!"
	testServiceSecret = "test-service-jwt-secret-distinct-32b!!"
)

func newPeerAuthMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("JWT_SECRET", testUserSecret)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", testServiceSecret)
	t.Setenv("AUTH_MODE", "codeployed")
	t.Setenv("OPA_AUTH_REQUIRED", "1")

	prevGate := authGate
	prevAuth := authEnforced
	t.Cleanup(func() {
		authGate = prevGate
		authEnforced = prevAuth
	})

	initAuthMode()
	setAuthEnforced(true)
	if authGate == nil {
		t.Fatal("expected auth gate")
	}

	mux := http.NewServeMux()
	authView := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, AuthMiddleware(h, "viewer"))
	}
	authAdmin := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, AuthMiddleware(h, "admin"))
	}
	registerSecurityRunsMux(mux, authView, authAdmin)
	registerGateMux(mux, authView, authAdmin)
	return mux
}

func mintPeerToken(t *testing.T, scope string) string {
	t.Helper()
	tok, err := openauth.MintServiceJWTWithOrg(
		[]byte(testServiceSecret), "ora-api", "osa-api", scope, "org-test", 0)
	if err != nil {
		t.Fatalf("mint service jwt: %v", err)
	}
	return tok
}

// The gate endpoint ora-api calls with scope findings:read must not 401.
func TestSecurityGateAcceptsPeerServiceJWT(t *testing.T) {
	mux := newPeerAuthMux(t)

	req := httptest.NewRequest(http.MethodGet,
		"/api/security/gate?security_run_id=srun-test&min_severity=high", nil)
	req.Header.Set("Authorization", "Bearer "+mintPeerToken(t, "findings:read"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("service JWT rejected on /api/security/gate: code=%d body=%s",
			rr.Code, rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected gate status: code=%d body=%s", rr.Code, rr.Body.String())
	}
}

// The run-create endpoint ora-api calls with scope "runs:write findings:read".
func TestSecurityRunsAcceptsPeerServiceJWT(t *testing.T) {
	mux := newPeerAuthMux(t)

	req := httptest.NewRequest(http.MethodPost, "/api/security/runs", nil)
	req.Header.Set("Authorization", "Bearer "+mintPeerToken(t, "runs:write findings:read"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("service JWT rejected on /api/security/runs: code=%d body=%s",
			rr.Code, rr.Body.String())
	}
}

// A service JWT signed with the wrong secret must still be rejected.
func TestSecurityGateRejectsForeignServiceSecret(t *testing.T) {
	mux := newPeerAuthMux(t)

	tok, err := openauth.MintServiceJWTWithOrg(
		[]byte("some-other-service-secret-32-bytes!!"), "ora-api", "osa-api",
		"findings:read", "org-test", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/api/security/gate?security_run_id=srun-test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("foreign-secret service JWT accepted: code=%d body=%s",
			rr.Code, rr.Body.String())
	}
}

// A service JWT for another audience must be rejected.
func TestSecurityGateRejectsForeignAudience(t *testing.T) {
	mux := newPeerAuthMux(t)

	tok, err := openauth.MintServiceJWTWithOrg(
		[]byte(testServiceSecret), "ora-api", "opl-api", "findings:read", "org-test", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/api/security/gate?security_run_id=srun-test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-audience service JWT accepted: code=%d body=%s",
			rr.Code, rr.Body.String())
	}
}
