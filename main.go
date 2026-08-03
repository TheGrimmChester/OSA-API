package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := env("LISTEN_ADDR", ":8093")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "osa-api"})
	})
	log.Printf("osa-api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
