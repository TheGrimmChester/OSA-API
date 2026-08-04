package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Vulnerability / IAST: vulnerability inventory + reachability ranking + IAST findings.

func registerVulnMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	mux.HandleFunc("/v1/sbom", handleSBOMIngest)
	authView("/api/vulns/summary", handleVulnSummary)
	authView("/api/vulns/findings", handleVulnFindings)
	authView("/api/vulns/inventory", handleVulnInventory)
	authAdmin("/api/vulns/match", handleVulnMatch)
	authView("/api/iast/findings", handleIASTFindings)
	authView("/api/iast/summary", handleIASTSummary)
}

// --- Advisory catalog (embedded subset; optional OSV enrichment later) ---

type advisory struct {
	ID          string
	Package     string
	Ecosystem   string
	Severity    string
	Summary     string
	Vulnerable  string // semver constraint hint, e.g. "<1.2.3"
	Symbols     []string
}

var embeddedAdvisories = []advisory{
	{
		ID: "GHSA-demo-lodash-proto", Package: "lodash", Ecosystem: "npm",
		Severity: "high", Summary: "Prototype pollution in lodash merge",
		Vulnerable: "<4.17.21", Symbols: []string{"lodash.merge", "_.merge"},
	},
	{
		ID: "GHSA-demo-axios-ssrf", Package: "axios", Ecosystem: "npm",
		Severity: "medium", Summary: "SSRF via absolute URL in axios request",
		Vulnerable: "<1.6.0", Symbols: []string{"axios", "axios.get"},
	},
	{
		ID: "GHSA-demo-requests-cve", Package: "requests", Ecosystem: "pypi",
		Severity: "medium", Summary: "Certificate verification bypass demo advisory",
		Vulnerable: "<2.31.0", Symbols: []string{"requests.get", "requests.session"},
	},
	{
		ID: "GHSA-demo-pillow-buffer", Package: "pillow", Ecosystem: "pypi",
		Severity: "high", Summary: "Buffer overflow in image decoder (demo)",
		Vulnerable: "<10.0.1", Symbols: []string{"PIL.Image", "Image.open"},
	},
	{
		ID: "GHSA-demo-symfony-http", Package: "symfony/http-foundation", Ecosystem: "composer",
		Severity: "high", Summary: "Request header injection (demo)",
		Vulnerable: "<6.4.0", Symbols: []string{"Request::create", "HeaderBag"},
	},
}

var advisoryExtraMu sync.RWMutex
var advisoryExtra []advisory

func allAdvisories() []advisory {
	advisoryExtraMu.RLock()
	defer advisoryExtraMu.RUnlock()
	out := make([]advisory, 0, len(embeddedAdvisories)+len(advisoryExtra))
	out = append(out, embeddedAdvisories...)
	out = append(out, advisoryExtra...)
	return out
}

// handleSBOMIngest accepts a simplified SBOM / package inventory JSON body.
// Shape:
//
//	{
//	  "service": "...", "release": "...", "ecosystem": "npm|pypi|composer|go",
//	  "organization_id": "", "project_id": "",
//	  "packages": [{"name":"lodash","version":"4.17.20","purl":"..."}]
//	}
func handleSBOMIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	body := http.MaxBytesReader(w, r.Body, 8<<20)
	defer body.Close()
	var payload struct {
		Service        string `json:"service"`
		Release        string `json:"release"`
		Ecosystem      string `json:"ecosystem"`
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		Packages       []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if payload.Service == "" {
		http.Error(w, "service required", 400)
		return
	}
	org := payload.OrganizationID
	proj := payload.ProjectID
	if org == "" {
		org, proj = tenantFromRequest(r)
	}
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	n := 0
	for _, p := range payload.Packages {
		if p.Name == "" {
			continue
		}
		q := fmt.Sprintf(`INSERT INTO opa.service_dependencies
			(organization_id, project_id, service, release, ecosystem, package_name, version, purl, scraped_at)
			VALUES ('%s','%s','%s','%s','%s','%s','%s','%s', now64(3))`,
			escapeSQL(org), escapeSQL(proj),
			escapeSQL(payload.Service), escapeSQL(payload.Release),
			escapeSQL(strings.ToLower(payload.Ecosystem)),
			escapeSQL(p.Name), escapeSQL(p.Version), escapeSQL(p.PURL))
		if _, err := queryClient.Query(q); err == nil {
			n++
		}
	}
	matched := matchAdvisoriesForService(org, proj, payload.Service, payload.Release, payload.Ecosystem)
	writeJSON(w, map[string]interface{}{"ok": true, "packages": n, "findings_upserted": matched})
}

func handleVulnMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	service := r.URL.Query().Get("service")
	release := r.URL.Query().Get("release")
	ecosystem := r.URL.Query().Get("ecosystem")
	org := r.Header.Get("X-Organization-Id")
	proj := r.Header.Get("X-Project-Id")
	n := matchAdvisoriesForService(org, proj, service, release, ecosystem)
	writeJSON(w, map[string]interface{}{"ok": true, "findings_upserted": n})
}

func matchAdvisoriesForService(org, proj, service, release, ecosystem string) int {
	if queryClient == nil {
		return 0
	}
	where := "1=1"
	if service != "" {
		where += fmt.Sprintf(" AND service = '%s'", escapeSQL(service))
	}
	if release != "" {
		where += fmt.Sprintf(" AND release = '%s'", escapeSQL(release))
	}
	if ecosystem != "" {
		where += fmt.Sprintf(" AND ecosystem = '%s'", escapeSQL(strings.ToLower(ecosystem)))
	}
	if org != "" {
		where += fmt.Sprintf(" AND organization_id = '%s'", escapeSQL(org))
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT organization_id, project_id, service, release, ecosystem, package_name, version
		FROM opa.service_dependencies
		WHERE %s
		ORDER BY scraped_at DESC
		LIMIT 5000`, where))
	if err != nil {
		return 0
	}
	n := 0
	for _, row := range rows {
		pkg := getString(row, "package_name")
		ver := getString(row, "version")
		eco := getString(row, "ecosystem")
		svc := getString(row, "service")
		rel := getString(row, "release")
		o := getString(row, "organization_id")
		p := getString(row, "project_id")
		for _, adv := range allAdvisories() {
			if !strings.EqualFold(adv.Package, pkg) {
				continue
			}
			if eco != "" && adv.Ecosystem != "" && !strings.EqualFold(adv.Ecosystem, eco) {
				continue
			}
			if !versionLikelyVulnerable(ver, adv.Vulnerable) {
				continue
			}
			reach, pathHash, hits := rankReachability(o, p, svc, adv)
			q := fmt.Sprintf(`INSERT INTO opa.vuln_findings
				(organization_id, project_id, service, release, ecosystem, package_name, version,
				 advisory_id, severity, summary, reachability, path_hash, path_hits, scraped_at)
				VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%d, now64(3))`,
				escapeSQL(o), escapeSQL(p), escapeSQL(svc), escapeSQL(rel), escapeSQL(eco),
				escapeSQL(pkg), escapeSQL(ver), escapeSQL(adv.ID), escapeSQL(adv.Severity),
				escapeSQL(adv.Summary), escapeSQL(reach), escapeSQL(pathHash), hits)
			if _, err := queryClient.Query(q); err == nil {
				n++
			}
		}
	}
	return n
}

// versionLikelyVulnerable is a deliberately simple comparator for demo advisories:
// if constraint is "<X.Y.Z" and version parses as lower, treat as vulnerable.
func versionLikelyVulnerable(version, constraint string) bool {
	version = strings.TrimSpace(version)
	constraint = strings.TrimSpace(constraint)
	if version == "" || constraint == "" {
		return true // unknown → keep finding; analyst ranks later
	}
	if strings.HasPrefix(constraint, "<") {
		return cmpSemver(version, strings.TrimPrefix(constraint, "<")) < 0
	}
	if strings.HasPrefix(constraint, "<=") {
		return cmpSemver(version, strings.TrimPrefix(constraint, "<=")) <= 0
	}
	return true
}

func cmpSemver(a, b string) int {
	as := parseSemverParts(a)
	bs := parseSemverParts(b)
	for i := 0; i < 3; i++ {
		if as[i] < bs[i] {
			return -1
		}
		if as[i] > bs[i] {
			return 1
		}
	}
	return 0
}

func parseSemverParts(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		fmt.Sscanf(parts[i], "%d", &out[i])
	}
	return out
}

// rankReachability joins advisory symbols against observed call-graph frames.
// Honesty: absence → "not_observed", never "not_vulnerable".
func rankReachability(org, proj, service string, adv advisory) (status, pathHash string, hits int64) {
	status = "not_observed"
	if queryClient == nil || len(adv.Symbols) == 0 {
		return
	}
	scope := ""
	if org != "" {
		scope += fmt.Sprintf(" AND organization_id = '%s'", escapeSQL(org))
	}
	if proj != "" {
		scope += fmt.Sprintf(" AND project_id = '%s'", escapeSQL(proj))
	}
	if service != "" {
		scope += fmt.Sprintf(" AND service = '%s'", escapeSQL(service))
	}
	// Prefer matching package name / symbols against call_site (file paths often include package).
	conds := make([]string, 0, len(adv.Symbols)+1)
	conds = append(conds, fmt.Sprintf("positionCaseInsensitive(call_site, '%s') > 0", escapeSQL(adv.Package)))
	for _, sym := range adv.Symbols {
		conds = append(conds, fmt.Sprintf("positionCaseInsensitive(call_site, '%s') > 0", escapeSQL(sym)))
	}
	// callgraph_agg is hub/agent telemetry in the opa DB — never rewrite to osa.
	sql := fmt.Sprintf(`
		SELECT path_hash, sum(samples) AS hits
		FROM opa.callgraph_agg
		WHERE bucket >= now() - INTERVAL 7 DAY%s
		  AND (%s)
		GROUP BY path_hash
		ORDER BY hits DESC
		LIMIT 1`, scope, strings.Join(conds, " OR "))
	rows, err := queryClient.QueryExact(sql)
	if err != nil || len(rows) == 0 {
		return
	}
	hits = int64(getFloat64(rows[0], "hits"))
	pathHash = getString(rows[0], "path_hash")
	if hits > 0 {
		status = "observed"
	}
	return
}

func handleVulnSummary(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	hours := clampInt(atoiDefault(r.URL.Query().Get("hours"), 168), 1, 720)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT
		  count() AS findings,
		  countIf(severity = 'critical') AS critical,
		  countIf(severity = 'high') AS high,
		  countIf(severity = 'medium') AS medium,
		  countIf(severity = 'low') AS low,
		  countIf(reachability = 'observed') AS observed,
		  countIf(reachability = 'not_observed') AS not_observed
		FROM opa.vuln_findings
		WHERE scraped_at >= now() - INTERVAL %d HOUR%s`, hours, scope))
	if err != nil || len(rows) == 0 {
		writeJSON(w, map[string]interface{}{"findings": 0})
		return
	}
	writeJSON(w, rows[0])
}

func handleVulnFindings(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 100), 1, 500)
	reach := r.URL.Query().Get("reachability")
	extra := ""
	if reach == "observed" || reach == "not_observed" {
		extra = fmt.Sprintf(" AND reachability = '%s'", escapeSQL(reach))
	}
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT service, release, ecosystem, package_name, version, advisory_id,
		       severity, summary, reachability, path_hash, path_hits, scraped_at
		FROM opa.vuln_findings
		WHERE 1=1%s%s
		ORDER BY multiIf(severity='critical',0, severity='high',1, severity='medium',2, 3) ASC,
		         path_hits DESC, scraped_at DESC
		LIMIT %d`, scope, extra, limit))
	if err != nil {
		writeJSON(w, map[string]interface{}{"findings": []interface{}{}, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"findings": rows})
}

func handleVulnInventory(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 200), 1, 1000)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT service, release, ecosystem, package_name, version, purl, max(scraped_at) AS scraped_at
		FROM opa.service_dependencies
		WHERE 1=1%s
		GROUP BY service, release, ecosystem, package_name, version, purl
		ORDER BY scraped_at DESC
		LIMIT %d`, scope, limit))
	if err != nil {
		writeJSON(w, map[string]interface{}{"packages": []interface{}{}, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"packages": rows})
}

func handleIASTSummary(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	hours := clampInt(atoiDefault(r.URL.Query().Get("hours"), 24), 1, 168)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT count() AS findings,
		       countIf(sink = 'sql') AS sql_sinks,
		       countIf(sink = 'command') AS command_sinks,
		       countIf(sink = 'file') AS file_sinks,
		       countIf(sink = 'deserialize') AS deserialize_sinks
		FROM opa.iast_findings
		WHERE scraped_at >= now() - INTERVAL %d HOUR%s`, hours, scope))
	if err != nil || len(rows) == 0 {
		writeJSON(w, map[string]interface{}{"findings": 0})
		return
	}
	writeJSON(w, rows[0])
}

func handleIASTFindings(w http.ResponseWriter, r *http.Request) {
	if queryClient == nil {
		http.Error(w, "not ready", 503)
		return
	}
	scope := tenantScopeSQL(r, queryClient, "")
	limit := clampInt(atoiDefault(r.URL.Query().Get("limit"), 100), 1, 500)
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT service, sink, evidence, route, trace_id, span_id, blocked, detector, scraped_at
		FROM opa.iast_findings
		WHERE 1=1%s
		ORDER BY scraped_at DESC
		LIMIT %d`, scope, limit))
	if err != nil {
		writeJSON(w, map[string]interface{}{"findings": []interface{}{}, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"findings": rows})
}

func recordIASTFinding(msg map[string]interface{}) {
	if queryClient == nil {
		return
	}
	sink := strFromMap(msg, "sink", "iast.sink")
	if sink == "" {
		return
	}
	blocked := 0
	switch v := msg["blocked"].(type) {
	case bool:
		if v {
			blocked = 1
		}
	case float64:
		if v != 0 {
			blocked = 1
		}
	case string:
		if v == "true" || v == "1" {
			blocked = 1
		}
	}
	detector := truncateStr(strFromMap(msg, "detector"), 128)
	q := fmt.Sprintf(`INSERT INTO opa.iast_findings
		(organization_id, project_id, service, sink, evidence, route, trace_id, span_id, blocked, detector, scraped_at)
		VALUES ('%s','%s','%s','%s','%s','%s','%s','%s', %d, '%s', now64(3))`,
		escapeSQL(strFromMap(msg, "organization_id")),
		escapeSQL(strFromMap(msg, "project_id")),
		escapeSQL(strFromMap(msg, "service")),
		escapeSQL(sink),
		escapeSQL(truncateStr(strFromMap(msg, "evidence", "message"), 1024)),
		escapeSQL(strFromMap(msg, "route", "http.route")),
		escapeSQL(strFromMap(msg, "trace_id")),
		escapeSQL(strFromMap(msg, "span_id")),
		blocked,
		escapeSQL(detector))
	_, _ = queryClient.Query(q)
}

func maybeRecordIASTFromRaw(raw json.RawMessage) {
	var msgType struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &msgType) != nil || msgType.Type != "iast" {
		return
	}
	var m map[string]interface{}
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	recordIASTFinding(m)
}
