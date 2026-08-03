package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	openauth "github.com/TheGrimmChester/open-auth-go"
	openjob "github.com/TheGrimmChester/open-job-go"
)

var (
	queryClient  *ClickHouseQuery
	writer       *ClickHouseWriter
	buildVersion = "osa-api-dev"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "orchestrator":
			runOrchestrator()
			return
		case "version":
			fmt.Println(buildVersion)
			return
		}
	}

	addr := envOr("LISTEN_ADDR", envOr("HTTP_ADDR", ":8093"))
	chURL := envOr("CLICKHOUSE_URL", "http://127.0.0.1:8123")

	writer = NewClickHouseWriter(chURL, 100)
	queryClient = NewClickHouseQuery(chURL)
	ensureClickHouseDatabase(queryClient)
	initAuthMode()

	authRequired := authRequiredEnv()
	authEnforced = authRequired
	if authRequired {
		log.Printf("auth: ENABLED (OPA_AUTH_REQUIRED)")
	} else {
		log.Printf("auth: disabled — endpoints open")
	}

	mux := http.NewServeMux()
	authView := func(pattern string, h http.HandlerFunc) {
		if authRequired {
			mux.HandleFunc(pattern, AuthMiddleware(h, "viewer"))
		} else {
			mux.HandleFunc(pattern, h)
		}
	}
	authAdmin := func(pattern string, h http.HandlerFunc) {
		if authRequired {
			mux.HandleFunc(pattern, AuthMiddleware(h, "admin"))
		} else {
			mux.HandleFunc(pattern, h)
		}
	}

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"status":    "ok",
			"service":   "osa-api",
			"version":   buildVersion,
			"database":  clickHouseDatabase(),
			"auth_mode": string(authMode),
		})
	})
	registerLocalAuthMux(mux)

	registerSecurityRunsMux(mux, authView, authAdmin)
	registerAppSecMux(mux, authView, authAdmin)
	registerAppSecDeepMux(mux, authView, authAdmin)
	registerVulnMux(mux, authView, authAdmin)
	registerGateMux(mux, authView, authAdmin)
	registerServiceAuthProbe(mux)

	srv := &http.Server{
		Addr:              addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("osa-api listening on %s (CH=%s db=%s)", addr, chURL, clickHouseDatabase())
	_ = openjob.RunnerImage("osa", "scan", envOr("OSA_RUNNER_TAG", "smoke"))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

// runOrchestrator is the osa-orchestrator entrypoint (same image, second command).
// It owns security-run job lifecycle and spawns one osa-runner-scan container per run.
func runOrchestrator() {
	addr := envOr("ORCHESTRATOR_LISTEN_ADDR", ":8095")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"service": "osa-orchestrator",
			"version": buildVersion,
			"runners": []string{openjob.RunnerImage("osa", "scan", envOr("OSA_RUNNER_TAG", "smoke"))},
		})
	})
	log.Printf("osa-orchestrator listening on %s (job scheduler; one container per security run)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func registerServiceAuthProbe(mux *http.ServeMux) {
	mux.HandleFunc("/api/peer/health", func(w http.ResponseWriter, r *http.Request) {
		secret := []byte(strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")))
		if len(secret) == 0 {
			writeJSON(w, map[string]interface{}{"status": "ok", "service_auth": "disabled"})
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", 401)
			return
		}
		claims, err := openauth.ValidateServiceJWT(strings.TrimPrefix(auth, "Bearer "), secret, "osa-api")
		if err != nil {
			http.Error(w, "invalid service token", 401)
			return
		}
		if err := openauth.RequireScope(claims, "health:read"); err != nil {
			http.Error(w, "missing scope", 403)
			return
		}
		writeJSON(w, map[string]interface{}{
			"status": "ok", "service": "osa-api", "iss": claims.Issuer, "scope": claims.Scope,
		})
	})
}
