package main

import (
	"net/http"
	"os"
	"strings"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// Peer auth for the AppSec control plane.
//
// ora-api delegates AppSec to osa-api with a short-lived service JWT
// (iss=ora-api, aud=osa-api) minted from OPEN_SERVICE_JWT_SECRET — see
// ORA-API/peer_osa.go. Routes registered with authView accept user JWTs only,
// so a service JWT fails ParseUserJWT and returns 401 "invalid token"; the CI
// gate then fails closed as peer_unavailable. Peer-callable routes must use
// registerPeerAuth instead, which accepts either credential.
//
// Scopes match what ora-api mints: reads require findings:read, writes require
// runs:write. Open when auth is disabled, matching authView/authAdmin.
func registerPeerAuth(mux *http.ServeMux, pattern, readScope, writeScope string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !authEnforced {
			h(w, r)
			return
		}
		scope := writeScope
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			scope = readScope
		}
		AuthUserOrServiceMiddleware(h, "viewer", scope)(w, r)
	})
}

// registerPeerServiceAuth is service-JWT-only (aud=osa-api). Used for peer fan-in
// routes that must never accept a dashboard/hub user JWT.
func registerPeerServiceAuth(mux *http.ServeMux, pattern, scope string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !authEnforced {
			h(w, r)
			return
		}
		token := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secret := []byte(strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")))
		if len(secret) == 0 {
			http.Error(w, "service auth disabled", http.StatusServiceUnavailable)
			return
		}
		sc, err := openauth.ValidateServiceJWT(token, secret, "osa-api")
		if err != nil {
			http.Error(w, "invalid service token", http.StatusUnauthorized)
			return
		}
		if scope != "" {
			if err := openauth.RequireScope(sc, scope); err != nil {
				http.Error(w, "missing scope", http.StatusForbidden)
				return
			}
		}
		r.Header.Del("X-Tenant-User-ID")
		r.Header.Set("X-User-Username", "service:"+sc.Issuer)
		r.Header.Set("X-User-Role", "admin")
		r.Header.Set("X-Service-Issuer", sc.Issuer)
		r.Header.Set("X-Service-Scope", sc.Scope)
		if org := strings.TrimSpace(sc.OrgID); org != "" {
			r.Header.Set("X-Organization-ID", org)
		}
		h(w, r)
	})
}
