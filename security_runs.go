package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func registerSecurityRunsMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authView("/api/security/profiles", handleSecurityProfiles)
	authView("/api/services", handleServices)
	// ora-api creates runs with a service JWT (scope "runs:write findings:read"),
	// so these two accept a user JWT or that service JWT — not user-only.
	// Trailing-slash subroutes must use the same auth gate as the collection —
	// plain HandleFunc would leave GET /api/security/runs/{id} open.
	registerPeerAuth(mux, "/api/security/runs", "findings:read", "runs:write", handleSecurityRuns)
	registerPeerAuth(mux, "/api/security/runs/", "findings:read", "runs:write", handleSecurityRunSub)
	_ = authAdmin
}

func securityRunID(parts ...string) string {
	return loadID("srun", parts...)
}

func securityRunIDFromBody(raw []byte) string {
	var body struct {
		SecurityRunID string `json:"security_run_id"`
		RunID         string `json:"run_id"`
	}
	_ = json.Unmarshal(raw, &body)
	return nz(body.SecurityRunID, body.RunID)
}

func handleSecurityProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	ws := securityWorkspaceRoot()
	secretsMode := secretsScannerMode()
	profiles := []map[string]interface{}{
		{"id": "auto", "label": "Auto-detect", "scanners": nil, "note": "Detect from workspace files"},
		{"id": "php", "label": "PHP", "scanners": securityProfileScanners("php")},
		{"id": "node", "label": "Node", "scanners": securityProfileScanners("node")},
		{"id": "container", "label": "Container", "scanners": securityProfileScanners("container")},
		{"id": "iac", "label": "IaC", "scanners": securityProfileScanners("iac")},
		{"id": "full", "label": "Full lite", "scanners": securityProfileScanners("full")},
	}
	secretsNote := "Embedded regex lite when gitleaks is unavailable"
	if secretsMode == "gitleaks" {
		secretsNote = "gitleaks CLI (default rules); falls back to embedded lite if the binary fails"
	}
	writeJSON(w, map[string]interface{}{
		"profiles":             profiles,
		"workspace":            ws,
		"workspace_role":       "fallback",
		"primary_target_model": "owner/repo",
		"peer_ora_configured":  peerORAURL() != "",
		"peer_opa_configured":  peerOPAURL() != "",
		"scanners": []map[string]interface{}{
			{"id": "secrets", "mode": secretsMode, "note": secretsNote, "aliases": []string{"gitleaks"}},
			{"id": "sast", "mode": "lite"},
			{"id": "iac", "mode": "stub"},
			{"id": "container", "mode": "stub"},
			{"id": "sbom", "mode": "lite"},
			{"id": "cve", "mode": "osv", "note": "Lockfile-only dependency CVE scan via OSV", "aliases": []string{"dependencies"}},
		},
		"gitleaks": map[string]interface{}{
			"available": secretsMode == "gitleaks",
			"bin_env":   "OPA_GITLEAKS_BIN",
		},
		"honesty": "Primary targets are GitHub owner/repo via hub tenancy + ORA connectors (ephemeral clones). Local OSA_SECURITY_WORKSPACE is a CI/fallback mount only. Secrets use gitleaks when installed; otherwise embedded lite. SAST/IaC/container remain lite/stub. IAST is runtime-only.",
	})
}

// serviceSourceTables are the tables that carry a `service` label, paired with the
// timestamp to report as last_seen. Findings can be ingested straight from CI
// without a security run (the /v1/security/* endpoints take a service name and no
// run id), so runs alone would miss services the dashboard has findings for.
var serviceSourceTables = []struct {
	table   string
	tsField string
	isRun   bool
}{
	{"security_runs", "started_at", true},
	{"secret_findings", "scraped_at", false},
	{"sast_findings", "scraped_at", false},
	{"iac_findings", "scraped_at", false},
	{"vuln_findings", "scraped_at", false},
	{"cve_findings", "scraped_at", false},
	{"iast_findings", "scraped_at", false},
}

// handleServices lists the service names this tenant's security corpus is filed
// under. The scan form's Service field reads it: before this existed the route
// 404'd and the dropdown offered only its two hardcoded smoke names.
//
// Each table is queried separately and individual failures are skipped rather
// than failing the request — one absent table (a database that predates a
// findings type, or a legacy install mid-backfill) must not blank the whole list.
func handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if queryClient == nil {
		writeJSON(w, map[string]interface{}{"services": []interface{}{}})
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	type agg struct {
		runs     int64
		findings int64
		lastSeen string
	}
	byName := map[string]*agg{}
	var degraded []string
	for _, src := range serviceSourceTables {
		rows, err := queryClient.Query(fmt.Sprintf(`
			SELECT service, count() AS n, max(%s) AS last_seen
			FROM opa.%s WHERE service != ''%s
			GROUP BY service ORDER BY service LIMIT 500`, src.tsField, src.table, scope))
		if err != nil {
			degraded = append(degraded, src.table)
			continue
		}
		for _, row := range rows {
			name := strings.TrimSpace(getString(row, "service"))
			if name == "" {
				continue
			}
			a := byName[name]
			if a == nil {
				a = &agg{}
				byName[name] = a
			}
			n := int64(atoiDefault(getString(row, "n"), 0))
			if src.isRun {
				a.runs += n
			} else {
				a.findings += n
			}
			// String compare is correct here: ClickHouse renders DateTime64 as
			// zero-padded "YYYY-MM-DD hh:mm:ss.sss", which sorts lexically.
			if ls := getString(row, "last_seen"); ls > a.lastSeen {
				a.lastSeen = ls
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	services := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		a := byName[name]
		services = append(services, map[string]interface{}{
			"name":      name,
			"runs":      a.runs,
			"findings":  a.findings,
			"last_seen": a.lastSeen,
		})
	}
	out := map[string]interface{}{"services": services}
	if len(degraded) > 0 {
		// Surfaced rather than swallowed: a short list because a table is missing
		// looks identical to a genuinely short list.
		out["unavailable_tables"] = degraded
		out["note"] = "Some finding tables could not be read; the list may be incomplete."
	}
	writeJSON(w, out)
}

func handleSecurityRuns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleSecurityRunsList(w, r)
	case http.MethodPost:
		handleSecurityRunCreate(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleSecurityRunsList(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		writeJSON(w, map[string]interface{}{"runs": []interface{}{}, "workspace": securityWorkspaceRoot()})
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 50), 1, 200)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT id, service, profile, scanners_json, target_path, image, status, summary_json, error, started_at, finished_at,
			repo_full_name, pr_number, commit_sha, scm_job_id
		FROM opa.security_runs WHERE 1=1%s
		ORDER BY started_at DESC LIMIT %d`, scope, limit))
	if err != nil {
		rows, err = queryClient.Query(fmt.Sprintf(`
			SELECT id, service, profile, scanners_json, target_path, image, status, summary_json, error, started_at, finished_at
			FROM opa.security_runs WHERE 1=1%s
			ORDER BY started_at DESC LIMIT %d`, scope, limit))
	}
	if err != nil {
		writeJSON(w, map[string]interface{}{"runs": []interface{}{}, "workspace": securityWorkspaceRoot(), "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"runs": rows, "workspace": securityWorkspaceRoot()})
}

func handleSecurityRunSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/security/runs/")
	path = strings.Trim(path, "/")
	if path == "" {
		handleSecurityRuns(w, r)
		return
	}
	parts := strings.Split(path, "/")
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		handleSecurityRunGet(w, r, id)
		return
	}
	if parts[1] == "findings" && r.Method == http.MethodGet {
		handleSecurityRunFindings(w, r, id)
		return
	}
	http.Error(w, "not found", 404)
}

func handleSecurityRunGet(w http.ResponseWriter, r *http.Request, id string) {
	if live := liveSecurityRun(id); live != nil {
		writeJSON(w, live)
		return
	}
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT id, service, profile, scanners_json, target_path, image, status, summary_json, error, started_at, finished_at,
			repo_full_name, pr_number, commit_sha, scm_job_id
		FROM opa.security_runs WHERE id = '%s'%s LIMIT 1`, escapeSQL(id), scope))
	if err != nil {
		rows, err = queryClient.Query(fmt.Sprintf(`
			SELECT id, service, profile, scanners_json, target_path, image, status, summary_json, error, started_at, finished_at
			FROM opa.security_runs WHERE id = '%s'%s LIMIT 1`, escapeSQL(id), scope))
	}
	if err != nil || len(rows) == 0 {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, rows[0])
}

func handleSecurityRunFindings(w http.ResponseWriter, r *http.Request, id string) {
	if queryClient == nil {
		writeJSON(w, map[string]interface{}{"security_run_id": id, "counts": map[string]int{}, "findings": map[string]interface{}{}})
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	rid := escapeSQL(id)
	count := func(table string) int {
		rows, err := queryClient.Query(fmt.Sprintf(`SELECT count() AS c FROM opa.%s WHERE security_run_id = '%s'%s`, table, rid, scope))
		if err != nil || len(rows) == 0 {
			return 0
		}
		return int(getFloat64(rows[0], "c"))
	}
	secrets, _ := queryClient.Query(fmt.Sprintf(`
		SELECT service, rule, file, line, severity, snippet, detector, security_run_id, scraped_at
		FROM opa.secret_findings WHERE security_run_id = '%s'%s ORDER BY scraped_at DESC LIMIT 200`, rid, scope))
	sast, _ := queryClient.Query(fmt.Sprintf(`
		SELECT service, rule, file, line, severity, message, security_run_id, scraped_at
		FROM opa.sast_findings WHERE security_run_id = '%s'%s ORDER BY scraped_at DESC LIMIT 200`, rid, scope))
	iac, _ := queryClient.Query(fmt.Sprintf(`
		SELECT service, kind, rule, file, severity, message, security_run_id, scraped_at
		FROM opa.iac_findings WHERE security_run_id = '%s'%s ORDER BY scraped_at DESC LIMIT 200`, rid, scope))
	if secrets == nil {
		secrets = []map[string]interface{}{}
	}
	if sast == nil {
		sast = []map[string]interface{}{}
	}
	if iac == nil {
		iac = []map[string]interface{}{}
	}
	cve, _ := queryClient.Query(fmt.Sprintf(`
		SELECT service, package_name, version, ecosystem, advisory_id, cve_id, severity, summary, security_run_id, scraped_at
		FROM opa.cve_findings WHERE security_run_id = '%s'%s ORDER BY scraped_at DESC LIMIT 200`, rid, scope))
	if cve == nil {
		cve = []map[string]interface{}{}
	}
	writeJSON(w, map[string]interface{}{
		"security_run_id": id,
		"counts": map[string]int{
			"secrets": count("secret_findings"),
			"sast":    count("sast_findings"),
			"iac":     count("iac_findings"),
			"cve":     count("cve_findings"),
		},
		"findings": map[string]interface{}{
			"secrets": secrets, "sast": sast, "iac": iac, "cve": cve,
		},
	})
}

type securityRunCreateBody struct {
	Service       string   `json:"service"`
	Profile       string   `json:"profile"`
	Scanners      []string `json:"scanners"`
	TargetPath    string   `json:"target_path"`
	Image         string   `json:"image"`
	Dispatch      *bool    `json:"dispatch"`
	RepoFullName  string   `json:"repo_full_name"`
	ConnectorID   string   `json:"connector_id"`
	Ref           string   `json:"ref"`
	PRNumber      int      `json:"pr_number"`
	CommitSHA     string   `json:"commit_sha"`
	SCMJobID      string   `json:"scm_job_id"`
	SecurityRunID string   `json:"security_run_id"`
}

func handleSecurityRunCreate(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	var body securityRunCreateBody
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	repo := strings.TrimSpace(body.RepoFullName)
	connectorID := strings.TrimSpace(body.ConnectorID)
	githubTarget := repo != "" && connectorID != ""
	if repo != "" && connectorID == "" {
		http.Error(w, "connector_id required with repo_full_name", 400)
		return
	}
	if connectorID != "" && (repo == "" || !strings.Contains(repo, "/")) {
		http.Error(w, "repo_full_name must be owner/repo when connector_id is set", 400)
		return
	}
	service := body.Service
	if service == "" {
		if githubTarget {
			service = "github-scan"
		} else {
			service = "workspace-scan"
		}
	}
	profile := nz(body.Profile, "auto")
	runID := nz(body.SecurityRunID, securityRunID(org, proj, service, time.Now().UTC().Format(time.RFC3339Nano)))
	scanners := normalizeSecurityScanners(body.Scanners)
	if len(scanners) == 0 {
		if profile == "auto" || profile == "" {
			if !githubTarget {
				root, rerr := resolveSecurityScanPath(body.TargetPath)
				if rerr == nil {
					scanners = detectSecurityScanners(root, body.Image)
				}
			}
			if len(scanners) == 0 {
				scanners = []string{"secrets", "sast"}
			}
		} else {
			scanners = securityProfileScanners(profile)
		}
	}
	dispatch := true
	if body.Dispatch != nil {
		dispatch = *body.Dispatch
	}
	scannersJSON, _ := json.Marshal(scanners)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	targetNote := body.TargetPath
	if githubTarget {
		targetNote = "ephemeral:" + repo
	}
	row := map[string]interface{}{
		"id": runID, "organization_id": org, "project_id": proj,
		"service": service, "profile": profile, "scanners_json": string(scannersJSON),
		"target_path": targetNote, "image": body.Image, "status": "queued",
		"summary_json": "{}", "error": "", "started_at": now, "finished_at": now,
		"repo_full_name": repo, "pr_number": body.PRNumber,
		"commit_sha": body.CommitSHA, "scm_job_id": body.SCMJobID,
	}
	rememberSecurityRun(row)
	if writer != nil {
		payload, _ := json.Marshal(row)
		writer.insertAsync("security_runs", append(payload, '\n'))
	}
	honesty := "Secrets via gitleaks when available, else embedded lite; other scanners remain lite/stub."
	if githubTarget {
		honesty += " Target is an ephemeral clone of " + repo + " (ORA clone credentials)."
	} else {
		honesty += " Fallback path scan against OSA_SECURITY_WORKSPACE when no connector_id/repo_full_name."
	}
	out := map[string]interface{}{
		"ok": true, "id": runID, "security_run_id": runID,
		"service": service, "profile": profile, "scanners": scanners,
		"repo_full_name": repo, "connector_id": connectorID,
		"honesty": honesty,
	}
	if dispatch {
		go runSecurityScanJob(runID, org, proj, service, profile, scanners, body.TargetPath, body.Image, repo, connectorID, body.Ref, body.PRNumber, body.CommitSHA, body.SCMJobID)
		out["dispatch"] = map[string]interface{}{"dispatched": true}
		out["status"] = "running"
	} else {
		out["dispatch"] = map[string]interface{}{"dispatched": false, "note": "dispatch=false — run record only"}
		out["status"] = "queued"
	}
	writeJSON(w, out)

}

var (
	securityRunLive sync.Map // id -> map[string]interface{}
)

func rememberSecurityRun(row map[string]interface{}) {
	id, _ := row["id"].(string)
	if id == "" {
		return
	}
	cp := map[string]interface{}{}
	for k, v := range row {
		cp[k] = v
	}
	securityRunLive.Store(id, cp)
}

func liveSecurityRun(id string) map[string]interface{} {
	if v, ok := securityRunLive.Load(id); ok {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func runSecurityScanJob(runID, org, proj, service, profile string, scanners []string, targetPath, image, repo, connectorID, ref string, pr int, sha, scmJob string) {
	githubTarget := strings.TrimSpace(repo) != "" && strings.TrimSpace(connectorID) != ""
	displayPath := targetPath
	if githubTarget {
		displayPath = "ephemeral:" + repo
	}
	base := map[string]interface{}{
		"id": runID, "organization_id": org, "project_id": proj,
		"service": service, "profile": profile, "target_path": displayPath, "image": image,
		"repo_full_name": repo, "pr_number": pr, "commit_sha": sha, "scm_job_id": scmJob,
	}
	if b, _ := json.Marshal(scanners); true {
		base["scanners_json"] = string(b)
	}
	updateSecurityRun(base, "running", "{}", "")

	var root string
	if githubTarget {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		cloned, cerr := ephemeralClone(ctx, connectorID, repo, ref, org)
		if cerr != nil {
			updateSecurityRun(base, "error", "{}", cerr.Error())
			return
		}
		root = cloned
		defer func() { _ = os.RemoveAll(filepath.Dir(cloned)) }()
	} else {
		var err error
		root, err = resolveSecurityScanPath(nz(targetPath, "."))
		if err != nil {
			updateSecurityRun(base, "error", "{}", err.Error())
			return
		}
		if st, serr := os.Stat(root); serr != nil || !st.IsDir() {
			if mkErr := os.MkdirAll(root, 0o755); mkErr != nil {
				updateSecurityRun(base, "error", "{}", fmt.Sprintf("workspace missing: %v", serr))
				return
			}
		}
	}

	counts := map[string]int{}
	severityCounts := map[string]map[string]int{}
	secretsDetector := ""
	secretsFilteredFP := 0
	var firstErr error
	for _, s := range scanners {
		var n int
		var e error
		switch s {
		case "secrets":
			var det string
			n, det, e = scanSecrets(runID, org, proj, service, root, scmJob)
			secretsDetector = det
			sev, fp := takeSecretSeverityCounts(runID)
			if len(sev) > 0 {
				severityCounts["secrets"] = sev
			}
			secretsFilteredFP = fp
		case "sast":
			n, e = scanSASTLite(runID, org, proj, service, root)
		case "iac":
			n, e = scanIaCStub(runID, org, proj, service, root)
		case "container":
			n, e = scanContainerStub(runID, org, proj, service, root, image)
		case "sbom":
			n, e = scanSBOMLite(runID, org, proj, service, root)
		case "cve":
			n, e = scanCVE(runID, org, proj, service, root, ref, pr, sha)
		}
		counts[s] = n
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	honesty := "lite/stub (+ gitleaks for secrets when available)."
	if githubTarget {
		honesty += " Scanned ephemeral clone of " + repo + "; credentials from ORA; clone removed after run."
	} else {
		honesty += " Fallback workspace path scan (OSA_SECURITY_WORKSPACE)."
	}
	summaryBody := map[string]interface{}{
		"counts": counts, "profile": profile, "root": root,
		"repo_full_name": repo, "ephemeral_clone": githubTarget,
		"honesty": honesty,
	}
	if len(severityCounts) > 0 {
		summaryBody["severity_counts"] = severityCounts
	}
	if secretsFilteredFP > 0 {
		summaryBody["secrets_filtered_fp"] = secretsFilteredFP
	}
	if secretsDetector != "" {
		summaryBody["secrets_detector"] = secretsDetector
	}
	summary, _ := json.Marshal(summaryBody)
	status := "completed"
	errMsg := ""
	if firstErr != nil {
		status = "completed_with_errors"
		errMsg = firstErr.Error()
	}
	updateSecurityRun(base, status, string(summary), errMsg)
}


func updateSecurityRun(base map[string]interface{}, status, summary, errMsg string) {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	row := map[string]interface{}{}
	for k, v := range base {
		row[k] = v
	}
	row["status"] = status
	row["summary_json"] = summary
	row["error"] = errMsg
	row["finished_at"] = now
	if _, ok := row["started_at"]; !ok {
		row["started_at"] = now
	}
	rememberSecurityRun(row)
	if writer == nil {
		return
	}
	payload, _ := json.Marshal(row)
	writer.insertAsync("security_runs", append(payload, '\n'))
}

// newRandomHex returns n hex chars from sha1 of time+pid.
func newRandomHex(n int) string {
	h := sha1.Sum([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())))
	s := hex.EncodeToString(h[:])
	if n > len(s) {
		n = len(s)
	}
	return s[:n]
}
