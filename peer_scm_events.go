package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
)

const (
	osaCheckerDependencies = "dependencies"
	osaCheckerRunName      = "OSA Dependencies"
)

func registerPeerSCMEventsMux(mux *http.ServeMux) {
	// Service-JWT-only: dashboard/hub user JWTs must not fan-in SCM scan triggers.
	registerPeerServiceAuth(mux, "/api/peer/scm/events", "scm:events", handlePeerSCMEvents)
}

type peerSCMEventBody struct {
	EventType      string   `json:"event_type"`
	OrganizationID string   `json:"organization_id"`
	ProjectID      string   `json:"project_id"`
	ConnectorID    string   `json:"connector_id"`
	RepoFullName   string   `json:"repo_full_name"`
	Ref            string   `json:"ref"`
	DefaultBranch  string   `json:"default_branch"`
	PRNumber       int      `json:"pr_number"`
	CommitSHA      string   `json:"commit_sha"`
	SCMJobID       string   `json:"scm_job_id"`
	ChangedPaths   []string `json:"changed_paths"`
	Checks         []string `json:"checks"`
	Dispatch       *bool    `json:"dispatch"`
}

type peerCheckerResult struct {
	ID           string `json:"id"`
	CheckRunName string `json:"check_run_name"`
	ShouldRun    bool   `json:"should_run"`
	Reason       string `json:"reason"`
	SecurityRunID string `json:"security_run_id,omitempty"`
	Status       string `json:"status,omitempty"`
}

func handlePeerSCMEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	var body peerSCMEventBody
	if json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	ctx, _ := ExtractTenantContext(r, queryClient)
	org, proj := ctx.WriteTenant()
	// Peer JWT org is authoritative — body cannot pivot into another tenant.
	if bodyOrg := strings.TrimSpace(body.OrganizationID); bodyOrg != "" && bodyOrg != org {
		http.Error(w, "organization_id mismatch with peer token", 403)
		return
	}
	if bodyProj := strings.TrimSpace(body.ProjectID); bodyProj != "" {
		proj = bodyProj
	}
	if !enforceWriteLocalityHTTP(w, r, org, proj) {
		return
	}
	if conn := strings.TrimSpace(body.ConnectorID); conn != "" {
		if err := verifyConnectorActiveViaService(r.Context(), conn, org); err != nil {
			http.Error(w, "connector not available for this organization", 403)
			return
		}
	}

	result := evaluateDependenciesChecker(body)
	if result.ShouldRun {
		dispatch := true
		if body.Dispatch != nil {
			dispatch = *body.Dispatch
		}
		runID, derr := createPeerCVESecurityRun(org, proj, body, dispatch)
		if derr != nil {
			result.ShouldRun = false
			result.Reason = "failed to create security run: " + derr.Error()
			result.Status = "error"
		} else {
			result.SecurityRunID = runID
			if dispatch {
				result.Status = "dispatched"
			} else {
				result.Status = "queued"
			}
		}
	}

	writeJSON(w, map[string]interface{}{
		"product":  "osa",
		"checkers": []peerCheckerResult{result},
	})
}

func evaluateDependenciesChecker(body peerSCMEventBody) peerCheckerResult {
	out := peerCheckerResult{
		ID:           osaCheckerDependencies,
		CheckRunName: osaCheckerRunName,
		ShouldRun:    false,
		Reason:       "event type not supported for dependency CVE scan",
	}
	if !peerSCMEventSupported(body.EventType, body.Ref, body.DefaultBranch) {
		return out
	}
	if len(body.Checks) > 0 && !peerChecksInclude(body.Checks, "osa:"+osaCheckerDependencies) {
		out.Reason = "dependencies checker not requested in checks filter"
		return out
	}
	ok, lock := changedPathsHaveLockfile(body.ChangedPaths)
	if !ok {
		out.Reason = "no dependency lockfiles in changed_paths"
		return out
	}
	repo := strings.TrimSpace(body.RepoFullName)
	connector := strings.TrimSpace(body.ConnectorID)
	if repo == "" || connector == "" {
		out.Reason = "repo_full_name and connector_id required to scan"
		return out
	}
	out.ShouldRun = true
	out.Reason = fmt.Sprintf("dependency lockfile changed: %s", lock)
	return out
}

func peerSCMEventSupported(eventType, ref, defaultBranch string) bool {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "pull_request", "pull_request.opened", "pull_request.synchronize":
		return true
	case "push.default":
		return true
	case "push":
		ref = strings.TrimPrefix(strings.TrimSpace(ref), "refs/heads/")
		def := strings.TrimSpace(defaultBranch)
		if def == "" {
			def = "main"
		}
		return ref == def
	default:
		return false
	}
}

func peerChecksInclude(checks []string, want string) bool {
	want = strings.ToLower(want)
	for _, c := range checks {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == want || c == osaCheckerDependencies {
			return true
		}
	}
	return false
}

func createPeerCVESecurityRun(org, proj string, body peerSCMEventBody, dispatch bool) (string, error) {
	repo := strings.TrimSpace(body.RepoFullName)
	connectorID := strings.TrimSpace(body.ConnectorID)
	service := "github-scan"
	runID := securityRunID(org, proj, service, time.Now().UTC().Format(time.RFC3339Nano))
	scanners := []string{"cve"}
	scannersJSON, _ := json.Marshal(scanners)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	row := map[string]interface{}{
		"id": runID, "organization_id": org, "project_id": proj,
		"service": service, "profile": "auto", "scanners_json": string(scannersJSON),
		"target_path": "ephemeral:" + repo, "image": "", "status": "queued",
		"summary_json": "{}", "error": "", "started_at": now, "finished_at": now,
		"repo_full_name": repo, "pr_number": body.PRNumber,
		"commit_sha": body.CommitSHA, "scm_job_id": body.SCMJobID,
	}
	rememberSecurityRun(row)
	if writer != nil {
		payload, _ := json.Marshal(row)
		writer.insertAsync("security_runs", append(payload, '\n'))
	}
	if dispatch {
		go runSecurityScanJob(runID, org, proj, service, "auto", scanners, "", "", repo, connectorID, body.Ref, body.PRNumber, body.CommitSHA, body.SCMJobID)
	}
	return runID, nil
}

// verifyConnectorActiveViaService lists ORA connectors with a service JWT scoped
// to orgID and requires connectorID to be active under that org.
func verifyConnectorActiveViaService(ctx context.Context, connectorID, orgID string) error {
	connectorID = strings.TrimSpace(connectorID)
	orgID = strings.TrimSpace(orgID)
	if connectorID == "" || orgID == "" {
		return fmt.Errorf("connector and org required")
	}
	if peerORAURL() == "" {
		return fmt.Errorf("PEER_ORA_URL not configured")
	}
	cfg := openclient.PeerFromEnv("PEER_ORA_URL", "osa-api", "ora-api", "connectors:read")
	cfg.OrgID = orgID
	var out map[string]interface{}
	if err := openclient.PeerJSON(ctx, cfg, http.MethodGet, "/api/connectors", nil, &out); err != nil {
		return err
	}
	list, _ := out["connectors"].([]interface{})
	filtered := filterConnectorsForOrg(list, orgID)
	if findConnectorInList(filtered, connectorID) == nil {
		return fmt.Errorf("connector not available")
	}
	return nil
}
