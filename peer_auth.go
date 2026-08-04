package main

import "net/http"

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
