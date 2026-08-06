package main

import (
	"encoding/json"
	"math"
	"strings"
	"sync"
)

// Scanners that contribute to the repository composite score.
// sbom is inventory-only and intentionally excluded.
var scoreScannerTypes = []string{"secrets", "sast", "iac", "cve", "container"}

// scannerSubscore computes a 0–100 score from severity counts for one scanner.
// Formula: max(0, 100 - 25*blocker - 20*critical - 10*high - 4*medium - 1*low); info ignored.
func scannerSubscore(sev map[string]int) float64 {
	if sev == nil {
		sev = map[string]int{}
	}
	penalty := 25*sev["blocker"] + 20*sev["critical"] + 10*sev["high"] + 4*sev["medium"] + 1*sev["low"]
	score := 100 - penalty
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return float64(score)
}

func sevCountGet(m map[string]int, keys ...string) int {
	n := 0
	for _, k := range keys {
		n += m[k]
	}
	return n
}

// repoScoreUpdateLocks serializes load→merge→persist per tenant+repo.
var repoScoreUpdateLocks sync.Map // key -> *sync.Mutex

func repoScoreUpdateLock(org, proj, repo string) *sync.Mutex {
	key := repoScoreCacheKey(org, proj, repo)
	v, _ := repoScoreUpdateLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ScannerFacet is the durable per-scanner slice of a repo score.
type ScannerFacet struct {
	Score      *float64 `json:"score"` // nil = never scanned
	RunID      string   `json:"run_id,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
	Severities map[string]int `json:"severities,omitempty"`
	FindingCount int    `json:"finding_count"`
}

// RepoScoreState is the mergeable rollup for one tenant+repo.
type RepoScoreState struct {
	OrganizationID string                   `json:"organization_id"`
	ProjectID      string                   `json:"project_id"`
	RepoFullName   string                   `json:"repo_full_name"`
	Score          *float64                 `json:"score"` // mean of known facets; nil if none
	Scanners       map[string]ScannerFacet  `json:"scanners"`
	ProblemCount   int                      `json:"problem_count"`
	UpdatedAt      string                   `json:"updated_at"`
	LastRunID      string                   `json:"last_run_id,omitempty"`
}

func emptyRepoScoreState(org, proj, repo string) *RepoScoreState {
	scanners := make(map[string]ScannerFacet, len(scoreScannerTypes))
	for _, s := range scoreScannerTypes {
		scanners[s] = ScannerFacet{}
	}
	return &RepoScoreState{
		OrganizationID: org,
		ProjectID:      proj,
		RepoFullName:   repo,
		Scanners:       scanners,
	}
}

// compositeScore returns the arithmetic mean of scanner facets that have a score.
func compositeScore(scanners map[string]ScannerFacet) (score *float64, problemCount int) {
	sum := 0.0
	n := 0
	problems := 0
	for _, id := range scoreScannerTypes {
		f, ok := scanners[id]
		if !ok || f.Score == nil {
			continue
		}
		sum += *f.Score
		n++
		problems += f.FindingCount
	}
	if n == 0 {
		return nil, 0
	}
	avg := math.Round(sum/float64(n)*10) / 10 // one decimal
	return &avg, problems
}

// mergeScannerFacets updates only the scanners that ran in this scan.
// Other facets are preserved so a secrets-only re-scan cannot wipe SAST history.
func mergeScannerFacets(prev *RepoScoreState, org, proj, repo, runID, updatedAt string, ran []string, sevByScanner map[string]map[string]int, counts map[string]int) *RepoScoreState {
	out := emptyRepoScoreState(org, proj, repo)
	if prev != nil {
		out.Scanners = make(map[string]ScannerFacet, len(scoreScannerTypes))
		for _, id := range scoreScannerTypes {
			if f, ok := prev.Scanners[id]; ok {
				out.Scanners[id] = f
			} else {
				out.Scanners[id] = ScannerFacet{}
			}
		}
		out.LastRunID = prev.LastRunID
	}
	ranSet := map[string]bool{}
	for _, s := range ran {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "dependencies" {
			s = "cve"
		}
		if s == "gitleaks" {
			s = "secrets"
		}
		ranSet[s] = true
	}
	updatedAny := false
	for _, id := range scoreScannerTypes {
		if !ranSet[id] {
			continue
		}
		sev := sevByScanner[id]
		if sev == nil {
			sev = map[string]int{}
		}
		// Prefer explicit severity map; fall back to total count as medium if only counts given.
		// Count only severities that affect the score (exclude info/unknown).
		findingCount := 0
		for k, v := range sev {
			lk := strings.ToLower(k)
			if lk == "info" || lk == "unknown" {
				continue
			}
			findingCount += v
		}
		if findingCount == 0 && counts != nil {
			if c, ok := counts[id]; ok && c > 0 {
				sev = map[string]int{"medium": c}
				findingCount = c
			}
		}
		sc := scannerSubscore(sev)
		out.Scanners[id] = ScannerFacet{
			Score:        &sc,
			RunID:        runID,
			UpdatedAt:    updatedAt,
			Severities:   sev,
			FindingCount: findingCount,
		}
		updatedAny = true
	}
	if !updatedAny {
		// SBOM-only (or other non-score) run — do not bump last_run_id / wipe timestamps.
		if prev != nil {
			return prev
		}
		return out
	}
	out.Score, out.ProblemCount = compositeScore(out.Scanners)
	out.UpdatedAt = updatedAt
	out.LastRunID = runID
	return out
}

// In-memory cache for rollups when ClickHouse is unavailable (tests / degraded mode).
var (
	repoScoreMu    sync.RWMutex
	repoScoreCache = map[string]*RepoScoreState{}
)

func repoScoreCacheKey(org, proj, repo string) string {
	return org + "\x00" + proj + "\x00" + repo
}

func rememberRepoScore(state *RepoScoreState) {
	if state == nil || state.RepoFullName == "" {
		return
	}
	repoScoreMu.Lock()
	defer repoScoreMu.Unlock()
	cp := *state
	scanners := make(map[string]ScannerFacet, len(state.Scanners))
	for k, v := range state.Scanners {
		scanners[k] = v
	}
	cp.Scanners = scanners
	repoScoreCache[repoScoreCacheKey(state.OrganizationID, state.ProjectID, state.RepoFullName)] = &cp
}

func loadRepoScoreCached(org, proj, repo string) *RepoScoreState {
	repoScoreMu.RLock()
	defer repoScoreMu.RUnlock()
	s := repoScoreCache[repoScoreCacheKey(org, proj, repo)]
	if s == nil {
		return nil
	}
	cp := *s
	scanners := make(map[string]ScannerFacet, len(s.Scanners))
	for k, v := range s.Scanners {
		scanners[k] = v
	}
	cp.Scanners = scanners
	return &cp
}

func listRepoScoresCached(org, proj string) []*RepoScoreState {
	repoScoreMu.RLock()
	defer repoScoreMu.RUnlock()
	out := []*RepoScoreState{}
	for _, s := range repoScoreCache {
		if s.OrganizationID == org && s.ProjectID == proj {
			cp := *s
			scanners := make(map[string]ScannerFacet, len(s.Scanners))
			for k, v := range s.Scanners {
				scanners[k] = v
			}
			cp.Scanners = scanners
			out = append(out, &cp)
		}
	}
	return out
}

func parseScannersJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	var arr []string
	if json.Unmarshal([]byte(raw), &arr) == nil {
		return normalizeSecurityScanners(arr)
	}
	return nil
}

func severityCountsFromSummary(summaryJSON string) (map[string]map[string]int, map[string]int) {
	sev := map[string]map[string]int{}
	counts := map[string]int{}
	var body struct {
		SeverityCounts map[string]map[string]int `json:"severity_counts"`
		Counts         map[string]int            `json:"counts"`
	}
	if json.Unmarshal([]byte(summaryJSON), &body) != nil {
		return sev, counts
	}
	if body.SeverityCounts != nil {
		sev = body.SeverityCounts
	}
	if body.Counts != nil {
		counts = body.Counts
	}
	return sev, counts
}
