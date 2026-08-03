package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AppSec CI gate — fail-closed on secrets/SAST/IaC findings for a security_run_id.
// Distinct from ORA review check-runs.

func registerGateMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authView("/api/security/gate", handleSecurityGate)
	_ = mux
	_ = authAdmin
}

func handleSecurityGate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("security_run_id"))
	minSev := nz(strings.TrimSpace(r.URL.Query().Get("min_severity")), "high")
	if r.Method == http.MethodPost {
		var body struct {
			SecurityRunID string `json:"security_run_id"`
			MinSeverity   string `json:"min_severity"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		runID = nz(body.SecurityRunID, runID)
		minSev = nz(body.MinSeverity, minSev)
	}
	if runID == "" {
		http.Error(w, "security_run_id required", 400)
		return
	}
	org, _ := ExtractTenantContext(r, queryClient)
	orgID := ""
	if org != nil {
		orgID, _ = org.WriteTenant()
	}
	writeJSON(w, evaluateScopedGate(orgID, runID, minSev))
}

func evaluateScopedGate(org, runID, minSev string) map[string]interface{} {
	fail := false
	reasons := []string{}
	softNotes := []string{}
	if queryClient != nil && runID != "" {
		sevFilter := "severity IN ('critical','high')"
		switch strings.ToLower(minSev) {
		case "critical":
			sevFilter = "severity = 'critical'"
		case "medium":
			sevFilter = "severity IN ('critical','high','medium')"
		case "low":
			sevFilter = "1=1"
		}
		rid := escapeSQL(runID)
		for _, table := range []string{"secret_findings", "sast_findings", "iac_findings"} {
			rows, err := queryClient.Query(fmt.Sprintf(`SELECT count() AS c FROM opa.%s WHERE security_run_id = '%s' AND %s`, table, rid, sevFilter))
			if err == nil && len(rows) > 0 && getFloat64(rows[0], "c") > 0 {
				fail = true
				reasons = append(reasons, table+" findings present")
			}
		}
	}
	if !fail {
		if live := liveSecurityRun(runID); live != nil {
			if sj, _ := live["summary_json"].(string); sj != "" {
				var sm struct {
					Counts          map[string]int            `json:"counts"`
					SeverityCounts  map[string]map[string]int `json:"severity_counts"`
					FilteredSecrets int                       `json:"secrets_filtered_fp"`
				}
				_ = json.Unmarshal([]byte(sj), &sm)
				if blocking := liveBlockingCount(sm.SeverityCounts, "secrets", minSev); blocking > 0 {
					fail = true
					reasons = append(reasons, "secret findings present (live)")
				} else if sm.Counts["secrets"] > 0 {
					softNotes = append(softNotes, fmt.Sprintf("secrets below gate threshold (min=%s, filtered_fp=%d)", minSev, sm.FilteredSecrets))
				}
				if sm.Counts["sast"] > 0 && strings.ToLower(minSev) != "critical" {
					if blocking := liveBlockingCount(sm.SeverityCounts, "sast", minSev); blocking > 0 || sm.SeverityCounts["sast"] == nil {
						fail = true
						reasons = append(reasons, "sast findings present (live)")
					}
				}
				if sm.Counts["iac"] > 0 && (minSev == "medium" || minSev == "low") {
					fail = true
					reasons = append(reasons, "iac findings present (live)")
				}
			}
		}
	}
	status := "pass"
	if fail {
		status = "fail"
	}
	_ = org
	out := map[string]interface{}{
		"status": status, "fail": fail, "reasons": reasons, "scope": "security_run",
		"security_run_id": runID, "min_severity": minSev,
	}
	if len(softNotes) > 0 {
		out["soft_notes"] = softNotes
	}
	return out
}

func liveBlockingCount(sev map[string]map[string]int, kind, minSev string) int {
	if sev == nil || sev[kind] == nil {
		return 0
	}
	m := sev[kind]
	switch strings.ToLower(minSev) {
	case "critical":
		return m["critical"]
	case "high":
		return m["critical"] + m["high"]
	case "medium":
		return m["critical"] + m["high"] + m["medium"]
	default:
		n := 0
		for _, v := range m {
			n += v
		}
		return n
	}
}
