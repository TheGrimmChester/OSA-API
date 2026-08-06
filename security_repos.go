package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

func registerSecurityReposMux(mux *http.ServeMux, authView func(string, http.HandlerFunc)) {
	authView("/api/security/repos", handleSecurityRepos)
	authView("/api/security/repos/", handleSecurityRepoSub)
}

func handleSecurityRepos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()

	rollups := loadAllRepoScores(org, proj)
	byRepo := map[string]*RepoScoreState{}
	for _, s := range rollups {
		byRepo[s.RepoFullName] = s
	}

	// Optional connector discovery to surface unscanned repos.
	connectorID := strings.TrimSpace(r.URL.Query().Get("connector_id"))
	discovered := []string{}
	var discoveryErr string
	if connectorID != "" {
		if msg, code := verifyConnectorActiveForRequest(r, connectorID); msg != "" {
			if code == 403 {
				http.Error(w, msg, 403)
				return
			}
			discoveryErr = msg
			log.Printf("discover repos: %s", msg)
		} else if peerORAURL() != "" {
			var err error
			discovered, err = discoverConnectorRepos(r, connectorID)
			if err != nil {
				discoveryErr = err.Error()
				log.Printf("discover repos: %v", err)
			}
		}
	}

	seen := map[string]bool{}
	repos := []map[string]interface{}{}
	for _, name := range discovered {
		name = strings.TrimSpace(name)
		if name == "" || !strings.Contains(name, "/") {
			continue
		}
		seen[name] = true
		repos = append(repos, repoListItem(name, byRepo[name]))
	}
	// Rollup-only repos (scanned but not in the current connector page).
	names := make([]string, 0, len(byRepo))
	for name := range byRepo {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		repos = append(repos, repoListItem(name, byRepo[name]))
	}

	out := map[string]interface{}{
		"repos":          repos,
		"score_scanners": scoreScannerTypes,
		"score_formula":  "per scanner: max(0, 100 - 25*blocker - 20*critical - 10*high - 4*medium - 1*low); repo = mean of measured scanners",
		"connector_id":   connectorID,
		"discovered":     len(discovered),
		"honesty":        "Composite score averages per-scanner facets. A single-scanner run updates only that facet.",
	}
	if discoveryErr != "" {
		out["discovery_error"] = discoveryErr
		out["honesty"] = out["honesty"].(string) + " Connector discovery failed — list may omit unscanned repos."
	}
	writeJSON(w, out)
}

func repoListItem(name string, state *RepoScoreState) map[string]interface{} {
	item := map[string]interface{}{
		"repo_full_name": name,
		"score":          nil,
		"problem_count":  0,
		"scanners":       map[string]interface{}{},
		"updated_at":     "",
		"last_run_id":    "",
	}
	facets := map[string]interface{}{}
	for _, id := range scoreScannerTypes {
		facets[id] = nil
	}
	if state != nil {
		item["score"] = state.Score
		item["problem_count"] = state.ProblemCount
		item["updated_at"] = state.UpdatedAt
		item["last_run_id"] = state.LastRunID
		for id, f := range state.Scanners {
			if f.Score != nil {
				facets[id] = map[string]interface{}{
					"score":         *f.Score,
					"run_id":        f.RunID,
					"updated_at":    f.UpdatedAt,
					"finding_count": f.FindingCount,
					"severities":    f.Severities,
				}
			}
		}
	}
	item["scanners"] = facets
	return item
}

func handleSecurityRepoSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/security/repos/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		http.Error(w, "expected /api/security/repos/{owner}/{repo}", 400)
		return
	}
	owner := parts[0]
	repoName := parts[1]
	rest := ""
	if len(parts) > 2 {
		rest = strings.Join(parts[2:], "/")
	}
	repo := owner + "/" + repoName
	if rest == "problems" || rest == "" {
		handleSecurityRepoDetail(w, r, repo, rest == "problems" || r.URL.Query().Get("view") == "problems")
		return
	}
	http.Error(w, "not found", 404)
}

func handleSecurityRepoDetail(w http.ResponseWriter, r *http.Request, repo string, problemsOnly bool) {
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	state := loadRepoScore(org, proj, repo)
	if state == nil {
		state = emptyRepoScoreState(org, proj, repo)
	}

	problems := loadRepoProblems(org, proj, state)
	runs := loadRepoRuns(org, proj, repo, 20)

	if problemsOnly {
		writeJSON(w, map[string]interface{}{
			"repo_full_name": repo,
			"problems":       problems,
			"counts":         problemCounts(problems),
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"repo_full_name": repo,
		"score":          state.Score,
		"problem_count":  state.ProblemCount,
		"scanners":       repoListItem(repo, state)["scanners"],
		"updated_at":     state.UpdatedAt,
		"last_run_id":    state.LastRunID,
		"problems":       problems,
		"runs":           runs,
		"score_formula":  "per scanner: max(0, 100 - 25*blocker - 20*critical - 10*high - 4*medium - 1*low); repo = mean of measured scanners",
		"honesty":        "Problems are taken from each scanner's latest contributing run, not only the newest overall run.",
	})
}

func problemCounts(problems []map[string]interface{}) map[string]int {
	out := map[string]int{}
	for _, p := range problems {
		s, _ := p["scanner"].(string)
		out[s]++
	}
	return out
}

func discoverConnectorRepos(r *http.Request, connectorID string) ([]string, error) {
	base := strings.TrimRight(peerORAURL(), "/")
	if base == "" || connectorID == "" {
		return nil, fmt.Errorf("peer ora not configured")
	}
	// ORA owns connectors at /api/connectors/{id}/repos — not /api/github/...
	raw, status, err := proxyPeerGET(r.Context(), base+"/api/connectors/"+connectorID+"/repos", r)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("peer status %d", status)
	}
	var body struct {
		Repos []map[string]interface{} `json:"repos"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil, fmt.Errorf("bad peer json")
	}
	out := []string{}
	for _, row := range body.Repos {
		name := firstNonEmpty(getString(row, "full_name"), getString(row, "repo_full_name"))
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

func loadAllRepoScores(org, proj string) []*RepoScoreState {
	cached := listRepoScoresCached(org, proj)
	if queryClient == nil {
		return cached
	}
	db := clickHouseDatabase()
	scope := fmt.Sprintf(" AND organization_id = '%s' AND project_id = '%s'", escapeSQL(org), escapeSQL(proj))
	// ORDER BY updated_at DESC + first-wins: ReplacingMergeTree may return multiple
	// versions; keep the newest only (do not let older rows overwrite later).
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT organization_id, project_id, repo_full_name, score, scanners_json, problem_count, updated_at, last_run_id
		FROM %s.repo_security_scores
		WHERE 1=1%s
		ORDER BY updated_at DESC
		LIMIT 2000`, db, scope))
	if err != nil || len(rows) == 0 {
		if len(cached) > 0 {
			return cached
		}
		return rowsToRepoScores(rows)
	}
	byKey := map[string]*RepoScoreState{}
	for _, row := range rows {
		s := decodeRepoScoreRow(row)
		if s == nil {
			continue
		}
		if _, exists := byKey[s.RepoFullName]; exists {
			continue // older version — already have newer from DESC order
		}
		byKey[s.RepoFullName] = s
	}
	for _, s := range cached {
		existing, ok := byKey[s.RepoFullName]
		if !ok || s.UpdatedAt >= existing.UpdatedAt {
			byKey[s.RepoFullName] = s
		}
	}
	merged := make([]*RepoScoreState, 0, len(byKey))
	for _, s := range byKey {
		merged = append(merged, s)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].RepoFullName < merged[j].RepoFullName
	})
	return merged
}

func rowsToRepoScores(rows []map[string]interface{}) []*RepoScoreState {
	out := []*RepoScoreState{}
	for _, row := range rows {
		s := decodeRepoScoreRow(row)
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

func decodeRepoScoreRow(row map[string]interface{}) *RepoScoreState {
	repo := getString(row, "repo_full_name")
	if repo == "" {
		return nil
	}
	s := emptyRepoScoreState(getString(row, "organization_id"), getString(row, "project_id"), repo)
	s.UpdatedAt = getString(row, "updated_at")
	s.LastRunID = getString(row, "last_run_id")
	s.ProblemCount = int(getFloat64(row, "problem_count"))
	if sc := getFloat64(row, "score"); row["score"] != nil && getString(row, "score") != "" {
		v := sc
		// Distinguish null score: ClickHouse may store -1 for "unscored".
		if raw := row["score"]; raw != nil {
			if f, ok := asFloat(raw); ok && f >= 0 {
				s.Score = &f
			}
		}
		_ = v
	}
	raw := getString(row, "scanners_json")
	if raw != "" && raw != "{}" {
		var facets map[string]ScannerFacet
		if json.Unmarshal([]byte(raw), &facets) == nil {
			for id, f := range facets {
				s.Scanners[id] = f
			}
		}
	}
	s.Score, s.ProblemCount = compositeScore(s.Scanners)
	return s
}

func asFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		if t == "" || t == "null" {
			return 0, false
		}
		var f float64
		if _, err := fmt.Sscanf(t, "%f", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func loadRepoScore(org, proj, repo string) *RepoScoreState {
	cached := loadRepoScoreCached(org, proj, repo)
	if queryClient == nil {
		return cached
	}
	db := clickHouseDatabase()
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT organization_id, project_id, repo_full_name, score, scanners_json, problem_count, updated_at, last_run_id
		FROM %s.repo_security_scores
		WHERE organization_id = '%s' AND project_id = '%s' AND repo_full_name = '%s'
		ORDER BY updated_at DESC LIMIT 1`,
		db, escapeSQL(org), escapeSQL(proj), escapeSQL(repo)))
	if err != nil || len(rows) == 0 {
		return cached
	}
	fromCH := decodeRepoScoreRow(rows[0])
	if fromCH == nil {
		return cached
	}
	if cached != nil && cached.UpdatedAt > fromCH.UpdatedAt {
		return cached
	}
	return fromCH
}

func persistRepoScore(state *RepoScoreState) {
	if state == nil {
		return
	}
	rememberRepoScore(state)
	if writer == nil {
		return
	}
	scoreVal := float64(-1)
	if state.Score != nil {
		scoreVal = *state.Score
	}
	scannersJSON, _ := json.Marshal(state.Scanners)
	row := map[string]interface{}{
		"organization_id": state.OrganizationID,
		"project_id":      state.ProjectID,
		"repo_full_name":  state.RepoFullName,
		"score":           scoreVal,
		"scanners_json":   string(scannersJSON),
		"problem_count":   state.ProblemCount,
		"updated_at":      state.UpdatedAt,
		"last_run_id":     state.LastRunID,
	}
	payload, _ := json.Marshal(row)
	writer.insertAsync("repo_security_scores", append(payload, '\n'))
}

// updateRepoScoreAfterRun merges scanner facets from a finished run into the rollup.
func updateRepoScoreAfterRun(org, proj, repo, runID, summaryJSON string, scanners []string, finishedAt string) {
	repo = strings.TrimSpace(repo)
	if repo == "" || !strings.Contains(repo, "/") {
		return
	}
	if finishedAt == "" {
		finishedAt = time.Now().UTC().Format("2006-01-02 15:04:05.000")
	}
	mu := repoScoreUpdateLock(org, proj, repo)
	mu.Lock()
	defer mu.Unlock()
	sev, counts := severityCountsFromSummary(summaryJSON)
	prev := loadRepoScore(org, proj, repo)
	next := mergeScannerFacets(prev, org, proj, repo, runID, finishedAt, scanners, sev, counts)
	if next == prev {
		return
	}
	persistRepoScore(next)
}

func loadRepoRuns(org, proj, repo string, limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 20
	}
	if queryClient == nil {
		return []map[string]interface{}{}
	}
	db := clickHouseDatabase()
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT id, service, profile, scanners_json, status, summary_json, error, started_at, finished_at,
			repo_full_name, commit_sha, ref
		FROM %s.security_runs
		WHERE organization_id = '%s' AND project_id = '%s' AND repo_full_name = '%s'
		ORDER BY started_at DESC LIMIT %d`,
		db, escapeSQL(org), escapeSQL(proj), escapeSQL(repo), limit))
	if err != nil || rows == nil {
		return []map[string]interface{}{}
	}
	return rows
}

func loadRepoProblems(org, proj string, state *RepoScoreState) []map[string]interface{} {
	out := []map[string]interface{}{}
	if state == nil || queryClient == nil {
		return out
	}
	type src struct {
		scanner string
		table   string
		cols    string
		extra   string
	}
	sources := []src{
		{"secrets", "secret_findings", "rule, severity, file, line, snippet, security_run_id, scraped_at", ""},
		{"sast", "sast_findings", "rule, severity, file, line, message, security_run_id, scraped_at", ""},
		{"iac", "iac_findings", "kind, rule, severity, file, message, security_run_id, scraped_at", " AND kind != 'container'"},
		{"cve", "cve_findings", "package_name, version, advisory_id, cve_id, severity, summary, security_run_id, scraped_at", ""},
	}
	db := clickHouseDatabase()
	for _, src := range sources {
		facet, ok := state.Scanners[src.scanner]
		if !ok || facet.RunID == "" {
			continue
		}
		q := fmt.Sprintf(`
			SELECT %s FROM %s.%s
			WHERE organization_id = '%s' AND project_id = '%s' AND security_run_id = '%s'%s
			ORDER BY scraped_at DESC LIMIT 200`,
			src.cols, db, src.table, escapeSQL(org), escapeSQL(proj), escapeSQL(facet.RunID), src.extra)
		rows, err := queryClient.Query(q)
		if err != nil {
			continue
		}
		for _, row := range rows {
			row["scanner"] = src.scanner
			title := firstNonEmpty(
				getString(row, "cve_id"),
				getString(row, "advisory_id"),
				getString(row, "rule"),
				getString(row, "message"),
				getString(row, "summary"),
			)
			row["title"] = title
			out = append(out, row)
		}
	}
	// container findings live in iac_findings with kind=container when stubbed
	if facet, ok := state.Scanners["container"]; ok && facet.RunID != "" {
		q := fmt.Sprintf(`
			SELECT kind, rule, severity, file, message, security_run_id, scraped_at FROM %s.iac_findings
			WHERE organization_id = '%s' AND project_id = '%s' AND security_run_id = '%s' AND kind = 'container'
			ORDER BY scraped_at DESC LIMIT 200`,
			db, escapeSQL(org), escapeSQL(proj), escapeSQL(facet.RunID))
		rows, _ := queryClient.Query(q)
		for _, row := range rows {
			row["scanner"] = "container"
			row["title"] = firstNonEmpty(getString(row, "rule"), getString(row, "message"))
			out = append(out, row)
		}
	}
	return out
}
