package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AppSec deep: SAST/IaC ingest, scanner token gate, PR-check expansion.

func registerAppSecDeepMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authView("/api/security/sast", handleSecuritySASTList)
	authView("/api/security/iac", handleSecurityIaCList)
	authView("/api/security/containers", handleSecurityIaCList) // container findings live in iac_findings (kind=container|image)
	mux.HandleFunc("/v1/security/sast", handleSecuritySASTIngest)
	mux.HandleFunc("/v1/security/iac", handleSecurityIaCIngest)
	mux.HandleFunc("/v1/security/containers", handleSecurityContainerIngest)
	_ = authAdmin
	_ = mux
}

// securityIngestAuthorized gates CI scanner ingest.
// Order: OSA_SECURITY_INGEST_TOKEN (Bearer / X-OSA-Security-Token) OR a valid
// app JWT session (password or OIDC login). When OPA_SECURITY_OIDC_REQUIRE=1,
// a configured OIDC issuer is mandatory and anonymous token-less ingest is denied
// even if OSA_SECURITY_INGEST_TOKEN is unset.
// Honesty: this is a pragmatic scanner gate — not a full IdP-bound AppSec SSO product.
func securityIngestAuthorized(r *http.Request) bool {
	oidcRequire := envOr("OPA_SECURITY_OIDC_REQUIRE", "0") == "1"
	if oidcRequire {
		issuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER"))
		if issuer == "" {
			issuer = strings.TrimSpace(os.Getenv("OPA_SECURITY_OIDC_ISSUER"))
		}
		if issuer == "" {
			return false
		}
	}
	want := strings.TrimSpace(os.Getenv("OSA_SECURITY_INGEST_TOKEN"))
	got := r.Header.Get("X-OSA-Security-Token")
	if got == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			got = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if want != "" && got == want {
		return true
	}
	// Accept dashboard / OIDC session JWT (same cookie/Bearer as AuthMiddleware).
	if securitySessionOK(r) {
		return true
	}
	if want == "" && !oidcRequire {
		return true // open ingest when no token configured (local/dev)
	}
	return false
}

func securitySessionOK(r *http.Request) bool {
	token := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	} else if c, err := r.Cookie(authCookieName); err == nil {
		token = c.Value
	}
	if token == "" {
		return false
	}
	ah := &AuthHandler{queryClient: queryClient}
	claims, err := ah.VerifyToken(token)
	if err != nil || claims == nil {
		return false
	}
	return hasPermission(claims.Role, "viewer")
}

func handleSecuritySASTIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !securityIngestAuthorized(r) {
		http.Error(w, "unauthorized — set Bearer / X-OSA-Security-Token (mint via OIDC session or OSA_SECURITY_INGEST_TOKEN)", 401)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var body struct {
		Findings []struct {
			Rule     string `json:"rule"`
			File     string `json:"file"`
			Line     int    `json:"line"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			Service  string `json:"service"`
		} `json:"findings"`
		Service       string `json:"service"`
		SecurityRunID string `json:"security_run_id"`
		RunID         string `json:"run_id"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	runID := nz(body.SecurityRunID, body.RunID)
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, f := range body.Findings {
		payload, _ := json.Marshal(map[string]interface{}{
			"organization_id": org, "project_id": proj,
			"service": nz(f.Service, body.Service), "rule": f.Rule, "file": f.File,
			"line": f.Line, "severity": nz(f.Severity, "medium"),
			"message": truncateStr(f.Message, 512), "security_run_id": runID, "scraped_at": now,
		})
		if writer != nil {
			writer.insertAsync("sast_findings", append(payload, '\n'))
		}
		n++
	}
	writeJSON(w, map[string]interface{}{"ok": true, "ingested": n, "security_run_id": runID})
}

func handleSecurityIaCIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !securityIngestAuthorized(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var body struct {
		Findings []struct {
			Kind     string `json:"kind"` // terraform|dockerfile|k8s|container
			Rule     string `json:"rule"`
			File     string `json:"file"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			Service  string `json:"service"`
		} `json:"findings"`
		Service       string `json:"service"`
		SecurityRunID string `json:"security_run_id"`
		RunID         string `json:"run_id"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	runID := nz(body.SecurityRunID, body.RunID)
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, f := range body.Findings {
		payload, _ := json.Marshal(map[string]interface{}{
			"organization_id": org, "project_id": proj,
			"service": nz(f.Service, body.Service), "kind": nz(f.Kind, "iac"),
			"rule": f.Rule, "file": f.File, "severity": nz(f.Severity, "medium"),
			"message": truncateStr(f.Message, 512), "security_run_id": runID, "scraped_at": now,
		})
		if writer != nil {
			writer.insertAsync("iac_findings", append(payload, '\n'))
		}
		n++
	}
	writeJSON(w, map[string]interface{}{"ok": true, "ingested": n, "security_run_id": runID})
}

func handleSecuritySASTList(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		writeJSON(w, map[string]interface{}{"findings": []interface{}{}})
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	extra := securityRunIDFilterSQL(r)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT service, rule, file, line, severity, message, security_run_id, scraped_at
		FROM opa.sast_findings WHERE 1=1%s%s ORDER BY scraped_at DESC LIMIT 200`, scope, extra))
	if err != nil {
		rows, err = queryClient.Query(fmt.Sprintf(`
			SELECT service, rule, file, line, severity, message, scraped_at
			FROM opa.sast_findings WHERE 1=1%s ORDER BY scraped_at DESC LIMIT 200`, scope))
		if err != nil {
			writeJSON(w, map[string]interface{}{"findings": []interface{}{}})
			return
		}
	}
	writeJSON(w, map[string]interface{}{"findings": rows})
}

func handleSecurityIaCList(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		writeJSON(w, map[string]interface{}{"findings": []interface{}{}})
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	kind := r.URL.Query().Get("kind")
	extra := securityRunIDFilterSQL(r)
	kindExtra := ""
	if kind != "" {
		kindExtra = fmt.Sprintf(" AND kind = '%s'", escapeSQL(kind))
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT service, kind, rule, file, severity, message, security_run_id, scraped_at
		FROM opa.iac_findings WHERE 1=1%s%s%s ORDER BY scraped_at DESC LIMIT 200`, scope, extra, kindExtra))
	if err != nil {
		rows, err = queryClient.Query(fmt.Sprintf(`
			SELECT service, kind, rule, file, severity, message, scraped_at
			FROM opa.iac_findings WHERE 1=1%s%s ORDER BY scraped_at DESC LIMIT 200`, scope, kindExtra))
		if err != nil {
			writeJSON(w, map[string]interface{}{"findings": []interface{}{}})
			return
		}
	}
	writeJSON(w, map[string]interface{}{"findings": rows})
}

func securityRunIDFilterSQL(r *http.Request) string {
	rid := strings.TrimSpace(r.URL.Query().Get("security_run_id"))
	if rid == "" {
		rid = strings.TrimSpace(r.URL.Query().Get("run_id"))
	}
	if rid == "" {
		return ""
	}
	return fmt.Sprintf(" AND security_run_id = '%s'", escapeSQL(rid))
}

// handleSecurityContainerIngest POST /v1/security/containers
// Stub image/container scan ingest — stores into iac_findings with kind=container|image.
// Honesty: not Trivy/Grype parity; accepts CI JSON findings only.
func handleSecurityContainerIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !securityIngestAuthorized(r) {
		http.Error(w, "unauthorized — set Bearer / X-OSA-Security-Token", 401)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var body struct {
		Image    string `json:"image"`
		Findings []struct {
			Rule     string `json:"rule"`
			Package  string `json:"package"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			CVE      string `json:"cve"`
			Service  string `json:"service"`
		} `json:"findings"`
		Service       string `json:"service"`
		SecurityRunID string `json:"security_run_id"`
		RunID         string `json:"run_id"`
	}
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	runID := nz(body.SecurityRunID, body.RunID)
	n := 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	img := nz(body.Image, "unknown-image")
	for _, f := range body.Findings {
		msg := f.Message
		if msg == "" && f.CVE != "" {
			msg = f.CVE
		}
		if f.Package != "" {
			msg = truncateStr(f.Package+": "+msg, 512)
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"organization_id": org, "project_id": proj,
			"service": nz(f.Service, body.Service), "kind": "container",
			"rule": nz(f.Rule, nz(f.CVE, "image_finding")), "file": img,
			"severity": nz(f.Severity, "medium"),
			"message": truncateStr(msg, 512), "security_run_id": runID, "scraped_at": now,
		})
		if writer != nil {
			writer.insertAsync("iac_findings", append(payload, '\n'))
		}
		n++
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "ingested": n, "image": img, "security_run_id": runID,
		"honesty": "Container/image finding ingest stub — not a full registry CVE scanner.",
	})
}
