package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	osvQueryPath       = "/v1/query"
	osvPositiveCacheTTL = 6 * time.Hour
	osvNegativeCacheTTL = 24 * time.Hour
)

var (
	cveCacheInst cveCache
	cveHTTPInst  *cveHTTPClient
	cveFlight    *singleflight
	osvAPIBase   = "https://api.osv.dev"
)

func initCVEStack() {
	maxBudget := clampInt(atoiDefault(envOr("OSA_CVE_BUDGET", "600"), 600), 1, 10000)
	budget := newCVEBudget(maxBudget)
	cveHTTPInst = newCVEHTTPClient(time.Duration(clampInt(atoiDefault(envOr("OSA_CVE_HTTP_TIMEOUT_SEC", "15"), 15), 5, 120))*time.Second, budget)
	osvAPIBase = strings.TrimRight(strings.TrimSpace(envOr("OSV_API_URL", "https://api.osv.dev")), "/")
	cveHTTPInst.allowHost(osvAPIBase)
	cveHTTPInst.limit(osvAPIBase, 5, 10)

	l1Max := clampInt(atoiDefault(envOr("OSA_CVE_L1_CACHE", "20000"), 20000), 1000, 100000)
	l1 := newMemCache(l1Max)
	var l2 *redisCache
	if rc, err := parseRedisURL(os.Getenv("REDIS_URL")); err == nil {
		l2 = rc
	}
	cveCacheInst = newLayeredCache(l1, l2)
	cveFlight = newSingleflight()
}

func osvEcosystemName(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "npm":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "composer", "packagist", "php":
		return "Packagist"
	case "go", "golang":
		return "Go"
	default:
		return eco
	}
}

func osvCacheKey(eco, pkg, version string) string {
	return fmt.Sprintf("src:osv:%s:%s:%s", strings.ToLower(osvEcosystemName(eco)), pkg, version)
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Details   string `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []osvRange `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

func queryOSV(ctx context.Context, eco, pkg, version string) ([]osvVuln, error) {
	if cveHTTPInst == nil || cveCacheInst == nil {
		return nil, fmt.Errorf("cve stack not initialized")
	}
	key := osvCacheKey(eco, pkg, version)
	if raw, ok := cveCacheInst.Get(ctx, key); ok {
		if isNegativeEntry(raw) {
			return nil, nil
		}
		var out osvQueryResponse
		if json.Unmarshal(raw, &out) == nil {
			return out.Vulns, nil
		}
	}
	raw, err := cveFlight.do(key, func() ([]byte, error) {
		if v, ok := cveCacheInst.Get(ctx, key); ok {
			return v, nil
		}
		body, _ := json.Marshal(map[string]interface{}{
			"package": map[string]string{"name": pkg, "ecosystem": osvEcosystemName(eco)},
			"version": version,
		})
		resp, err := cveHTTPInst.postJSON(ctx, osvAPIBase+osvQueryPath, body, cveBodyLimitDefault)
		if err != nil {
			return nil, err
		}
		if len(resp) == 0 {
			cveCacheInst.Set(ctx, key, negativeEntry, osvNegativeCacheTTL)
			return negativeEntry, nil
		}
		var parsed osvQueryResponse
		if json.Unmarshal(resp, &parsed) != nil {
			return resp, nil
		}
		if len(parsed.Vulns) == 0 {
			cveCacheInst.Set(ctx, key, negativeEntry, osvNegativeCacheTTL)
			return negativeEntry, nil
		}
		cveCacheInst.Set(ctx, key, resp, osvPositiveCacheTTL)
		return resp, nil
	})
	if err != nil {
		return nil, err
	}
	if isNegativeEntry(raw) {
		return nil, nil
	}
	var out osvQueryResponse
	if json.Unmarshal(raw, &out) != nil {
		return nil, fmt.Errorf("osv json decode failed")
	}
	return out.Vulns, nil
}

func osvSeverityBand(v osvVuln) (band string, score float32, vector, version, source string) {
	band = "unknown"
	for _, sev := range v.Severity {
		if strings.Contains(strings.ToUpper(sev.Type), "CVSS") && strings.TrimSpace(sev.Score) != "" {
			vector = sev.Score
			source = sev.Type
			if i := strings.Index(sev.Score, "/"); i > 0 {
				version = sev.Score[:i]
			}
			if i := strings.LastIndex(sev.Score, ":"); i >= 0 && i+1 < len(sev.Score) {
				if f, err := parseFloat32(sev.Score[i+1:]); err == nil {
					score = f
					switch {
					case score >= 9:
						band = "critical"
					case score >= 7:
						band = "high"
					case score >= 4:
						band = "medium"
					case score > 0:
						band = "low"
					}
				}
			}
			return
		}
	}
	if ds, ok := v.DatabaseSpecific["severity"].(string); ok && ds != "" {
		band = strings.ToLower(ds)
	}
	return
}

func parseFloat32(s string) (float32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return float32(f), err
}

func primaryCVEID(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return a
		}
	}
	return ""
}

func scanCVE(runID, org, proj, service, root, ref string, pr int, sha string) (int, error) {
	deps, err := collectLockfileDeps(root)
	if err != nil {
		return 0, err
	}
	if len(deps) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, dep := range deps {
		insertFindingRow("service_dependencies", map[string]interface{}{
			"organization_id": org, "project_id": proj,
			"service": service, "release": ref, "ecosystem": strings.ToLower(dep.Ecosystem),
			"package_name": dep.Package, "version": dep.Version, "purl": "",
			"scraped_at": now,
		})
	}

	pkgs := make([]string, 0, len(deps))
	for _, d := range deps {
		pkgs = append(pkgs, d.Package)
	}
	reach := rankReachabilityBatch(org, proj, service, pkgs)

	n := 0
	budgetExhausted := false
	for _, dep := range deps {
		vulns, qerr := queryOSV(ctx, dep.Ecosystem, dep.Package, dep.Version)
		if qerr != nil {
			if qerr == errBudgetExhausted {
				budgetExhausted = true
				break
			}
			continue
		}
		rh := reach[dep.Package]
		for _, v := range vulns {
			if n >= 5000 {
				break
			}
			var ranges []osvRange
			for _, aff := range v.Affected {
				if aff.Package.Name != "" && !strings.EqualFold(aff.Package.Name, dep.Package) {
					continue
				}
				ranges = append(ranges, aff.Ranges...)
			}
			fixed, fixState := nearestFix(ranges, dep.Version)
			intro := introducedVersion(ranges)
			sev, cvssScore, cvssVector, cvssVer, cvssSrc := osvSeverityBand(v)
			cveID := primaryCVEID(v)
			aliasesJSON, _ := json.Marshal(v.Aliases)
			refsJSON, _ := json.Marshal(v.References)
			summary := nz(v.Summary, v.Details)
			if len(summary) > 1024 {
				summary = summary[:1024]
			}

			insertFindingRow("cve_findings", map[string]interface{}{
				"organization_id": org, "project_id": proj,
				"security_run_id": runID, "service": service,
				"ref": ref, "pr_number": pr, "commit_sha": sha,
				"ecosystem": strings.ToLower(dep.Ecosystem),
				"package_name": dep.Package, "version": dep.Version,
				"dep_scope": nz(dep.Scope, "unknown"), "dep_depth": dep.Depth,
				"manifest": dep.Manifest,
				"advisory_id": v.ID, "cve_id": cveID,
				"aliases_json": string(aliasesJSON),
				"severity": sev, "cvss_score": cvssScore,
				"cvss_vector": cvssVector, "cvss_version": cvssVer, "cvss_source": cvssSrc,
				"fixed_version": fixed, "fix_state": fixState,
				"introduced_version": intro,
				"reachability": rh.Status, "path_hash": rh.PathHash, "path_hits": rh.Hits,
				"summary": summary,
				"references_json": string(refsJSON),
				"published_at": v.Published, "modified_at": v.Modified,
				"scraped_at": now,
			})
			insertFindingRow("vuln_findings", map[string]interface{}{
				"organization_id": org, "project_id": proj,
				"service": service, "release": ref,
				"ecosystem": strings.ToLower(dep.Ecosystem),
				"package_name": dep.Package, "version": dep.Version,
				"advisory_id": v.ID, "severity": sev, "summary": summary,
				"reachability": rh.Status, "path_hash": rh.PathHash, "path_hits": rh.Hits,
				"cve_id": cveID, "cvss_score": cvssScore,
				"fixed_version": fixed, "security_run_id": runID,
				"scraped_at": now,
			})
			n++
		}
	}
	if budgetExhausted {
		return n, errBudgetExhausted
	}
	return n, nil
}
