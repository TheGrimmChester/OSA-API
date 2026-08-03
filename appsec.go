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

// AppSec hub — OSV enrichment, secret findings, PR-check helpers.

func registerAppSecMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authView("/api/security/secrets", handleSecuritySecretsList)
	authView("/api/security/policies", handleSecurityPolicies)
	authView("/api/security/pr-check", handleSecurityPRCheck)
	mux.HandleFunc("/v1/security/secrets", handleSecuritySecretsIngest)
	mux.HandleFunc("/v1/security/pr-check", handleSecurityPRCheckCI)
	authAdmin("/api/security/osv/enrich", handleOSVEnrich)
	_ = mux
}

// handleSecurityPRCheckCI is the token-gated CI entry (same body as dashboard PR-check).
func handleSecurityPRCheckCI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !securityIngestAuthorized(r) {
		http.Error(w, "unauthorized — OSA_SECURITY_INGEST_TOKEN or viewer session required", 401)
		return
	}
	handleSecurityPRCheck(w, r)
}

func handleSecuritySecretsIngest(w http.ResponseWriter, r *http.Request) {
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
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	var body struct {
		Findings []struct {
			Rule     string `json:"rule"`
			File     string `json:"file"`
			Line     int    `json:"line"`
			Severity string `json:"severity"`
			Snippet  string `json:"snippet"`
			Service  string `json:"service"`
			Detector string `json:"detector"`
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
			"line": f.Line, "severity": nz(f.Severity, "high"),
			"snippet": truncateStr(f.Snippet, 256), "detector": nz(f.Detector, "ci"),
			"security_run_id": runID, "scraped_at": now,
		})
		if writer != nil {
			writer.insertAsync("secret_findings", append(payload, '\n'))
		}
		n++
	}
	writeJSON(w, map[string]interface{}{"ok": true, "ingested": n, "security_run_id": runID})
}

func handleSecuritySecretsList(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		writeJSON(w, map[string]interface{}{"findings": []interface{}{}})
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 100), 1, 500)
	extra := securityRunIDFilterSQL(r)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT service, rule, file, line, severity, snippet, detector, security_run_id, scraped_at
		FROM opa.secret_findings WHERE 1=1%s%s
		ORDER BY scraped_at DESC LIMIT %d`, scope, extra, limit))
	if err != nil {
		// Pre-migration 0033 fallback without security_run_id column.
		rows, err = queryClient.Query(fmt.Sprintf(`
			SELECT service, rule, file, line, severity, snippet, detector, scraped_at
			FROM opa.secret_findings WHERE 1=1%s
			ORDER BY scraped_at DESC LIMIT %d`, scope, limit))
		if err != nil {
			writeJSON(w, map[string]interface{}{"findings": []interface{}{}})
			return
		}
	}
	writeJSON(w, map[string]interface{}{"findings": rows})
}

func handleSecurityPolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"min_severity":          envOr("OPA_SECURITY_MIN_SEVERITY", "high"),
		"fail_on_observed_vuln": envOr("OPA_SECURITY_FAIL_OBSERVED", "1") == "1",
		"fail_on_secrets":       true,
		"note":                  "Policy thresholds for CI PR checks; Dashboard may override locally.",
	})
}

func handleSecurityPRCheck(w http.ResponseWriter, r *http.Request) {
	minSev := strings.ToLower(envOr("OPA_SECURITY_MIN_SEVERITY", "high"))
	q := r.URL.Query()
	runID := strings.TrimSpace(q.Get("security_run_id"))
	repo := strings.TrimSpace(q.Get("repo"))
	sha := strings.TrimSpace(q.Get("sha"))
	if r.Method == http.MethodPost && (runID == "" && repo == "" && sha == "") {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var body struct {
			SecurityRunID string `json:"security_run_id"`
			Repo          string `json:"repo"`
			RepoFullName  string `json:"repo_full_name"`
			SHA           string `json:"sha"`
			CommitSHA     string `json:"commit_sha"`
			PR            int    `json:"pr"`
			MinSeverity   string `json:"min_severity"`
		}
		if json.Unmarshal(raw, &body) == nil {
			runID = nz(runID, body.SecurityRunID)
			repo = nz(repo, nz(body.Repo, body.RepoFullName))
			sha = nz(sha, nz(body.SHA, body.CommitSHA))
			if body.MinSeverity != "" {
				minSev = strings.ToLower(body.MinSeverity)
			}
			_ = body.PR
		}
	}
	scoped := runID != "" || repo != "" || sha != ""
	fail := false
	reasons := []string{}
	scopeMode := "tenant"
	if queryClient != nil {
		scope := tenantScopeSQL(r, queryClient, "")
		sevFilter := "severity IN ('critical','high')"
		if minSev == "critical" {
			sevFilter = "severity = 'critical'"
		} else if minSev == "medium" {
			sevFilter = "severity IN ('critical','high','medium')"
		} else if minSev == "low" {
			sevFilter = "severity IN ('critical','high','medium','low')"
		}
		runFilter := ""
		if runID != "" {
			runFilter = fmt.Sprintf(" AND security_run_id = '%s'", escapeSQL(runID))
			scopeMode = "security_run"
		} else if repo != "" || sha != "" {
			// Scoped by repo/sha via security_runs join when columns exist.
			extra := []string{}
			if repo != "" {
				extra = append(extra, fmt.Sprintf("repo_full_name = '%s'", escapeSQL(repo)))
			}
			if sha != "" {
				extra = append(extra, fmt.Sprintf("commit_sha = '%s'", escapeSQL(sha)))
			}
			rows, err := queryClient.Query(fmt.Sprintf(`
				SELECT id FROM opa.security_runs WHERE %s%s ORDER BY started_at DESC LIMIT 20`,
				strings.Join(extra, " AND "), scope))
			if err == nil && len(rows) > 0 {
				ids := make([]string, 0, len(rows))
				for _, row := range rows {
					ids = append(ids, "'"+escapeSQL(getString(row, "id"))+"'")
				}
				runFilter = fmt.Sprintf(" AND security_run_id IN (%s)", strings.Join(ids, ","))
				scopeMode = "repo_sha"
			} else {
				scopeMode = "repo_sha_empty"
			}
		}
		if !scoped {
			if rows, err := queryClient.Query(fmt.Sprintf(`
				SELECT count() AS c FROM opa.vuln_findings
				WHERE reachability = 'observed' AND severity IN ('critical','high') %s`, scope)); err == nil && len(rows) > 0 {
				if getFloat64(rows[0], "c") > 0 {
					fail = true
					reasons = append(reasons, "observed high/critical vulns")
				}
			}
		}
		if scopeMode != "repo_sha_empty" {
			if rows, err := queryClient.Query(fmt.Sprintf(`
				SELECT count() AS c FROM opa.secret_findings WHERE %s %s%s`, sevFilter, scope, runFilter)); err == nil && len(rows) > 0 {
				if getFloat64(rows[0], "c") > 0 {
					fail = true
					reasons = append(reasons, "secret findings present")
				}
			}
			if rows, err := queryClient.Query(fmt.Sprintf(`
				SELECT count() AS c FROM opa.sast_findings WHERE %s %s%s`, sevFilter, scope, runFilter)); err == nil && len(rows) > 0 {
				if getFloat64(rows[0], "c") > 0 {
					fail = true
					reasons = append(reasons, "sast findings present")
				}
			}
			if rows, err := queryClient.Query(fmt.Sprintf(`
				SELECT count() AS c FROM opa.iac_findings WHERE %s %s%s`, sevFilter, scope, runFilter)); err == nil && len(rows) > 0 {
				if getFloat64(rows[0], "c") > 0 {
					fail = true
					reasons = append(reasons, "iac/container findings present")
				}
			}
		}
	}
	status := "pass"
	if fail {
		status = "fail"
	}
	writeJSON(w, map[string]interface{}{
		"status": status, "fail": fail, "reasons": reasons, "min_severity": minSev,
		"scope":            scopeMode,
		"security_run_id":  runID,
		"repo":             repo,
		"sha":              sha,
		"ci_snippet":       "curl -fsS -H \"X-OSA-Security-Token: $OSA_SECURITY_INGEST_TOKEN\" -X POST \"$OSA_API_URL/v1/security/pr-check\"",
		"ci_snippet_scoped": "curl -fsS -H \"X-OSA-Security-Token: $OSA_SECURITY_INGEST_TOKEN\" -X POST \"$OSA_API_URL/v1/security/pr-check\" -H 'Content-Type: application/json' -d '{\"security_run_id\":\"srun-…\"}'",
		"scanner_auth": map[string]interface{}{
			"token_required":  strings.TrimSpace(os.Getenv("OSA_SECURITY_INGEST_TOKEN")) != "",
			"oidc_require":    envOr("OPA_SECURITY_OIDC_REQUIRE", "0") == "1",
			"oidc_configured": strings.TrimSpace(os.Getenv("OIDC_ISSUER")) != "" || strings.TrimSpace(os.Getenv("OPA_SECURITY_OIDC_ISSUER")) != "",
			"oidc_login":      "/api/auth/oidc/login",
			"note":            "CI: OSA_SECURITY_INGEST_TOKEN on /v1/security/* and PR-check when gated. Prefer scoped body {security_run_id} for Repo Watch jobs. Humans: OIDC/password JWT session.",
			"honesty":         "Pragmatic scanner SSO gate reusing app OIDC/JWT — not a dedicated AppSec IdP product.",
		},
	})
}

func handleOSVEnrich(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("OPA_OSV") != "1" {
		writeJSON(w, map[string]interface{}{
			"ok": false, "skipped": true,
			"note": "Set OPA_OSV=1 to call api.osv.dev for package advisories.",
		})
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT DISTINCT package_name, version, ecosystem, service
		FROM opa.service_dependencies
		WHERE organization_id = '%s' AND project_id = '%s'
		LIMIT 50`, escapeSQL(org), escapeSQL(proj)))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	matched := 0
	client := &http.Client{Timeout: 12 * time.Second}
	for _, row := range rows {
		pkg := getString(row, "package_name")
		ver := getString(row, "version")
		eco := nz(getString(row, "ecosystem"), "npm")
		osvEco := map[string]string{"npm": "npm", "pypi": "PyPI", "composer": "Packagist", "go": "Go"}[strings.ToLower(eco)]
		if osvEco == "" {
			osvEco = eco
		}
		body, _ := json.Marshal(map[string]interface{}{
			"package": map[string]string{"name": pkg, "ecosystem": osvEco},
			"version": ver,
		})
		req, err := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/query", strings.NewReader(string(body)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			continue
		}
		var out struct {
			Vulns []struct {
				ID      string `json:"id"`
				Summary string `json:"summary"`
			} `json:"vulns"`
		}
		if json.Unmarshal(raw, &out) != nil {
			continue
		}
		for _, v := range out.Vulns {
			q := fmt.Sprintf(`INSERT INTO opa.vuln_findings
				(organization_id, project_id, service, package_name, version, advisory_id, severity, summary, reachability, path_hash, path_hits, scraped_at)
				VALUES ('%s','%s','%s','%s','%s','%s','high','%s','not_observed','',0, now64(3))`,
				escapeSQL(org), escapeSQL(proj), escapeSQL(getString(row, "service")),
				escapeSQL(pkg), escapeSQL(ver), escapeSQL(v.ID),
				escapeSQL(truncateStr(v.Summary, 512)))
			_, _ = queryClient.Query(q)
			matched++
		}
	}
	writeJSON(w, map[string]interface{}{"ok": true, "matched": matched, "packages": len(rows)})
}
