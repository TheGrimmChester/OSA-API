package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

func newPeerSCMMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("JWT_SECRET", testUserSecret)
	t.Setenv("OPEN_SERVICE_JWT_SECRET", testServiceSecret)
	t.Setenv("AUTH_MODE", "codeployed")
	t.Setenv("OPA_AUTH_REQUIRED", "1")

	ora := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/connectors" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"connectors": []map[string]interface{}{
					{"id": "conn-1", "status": "active", "organization_id": "org-test"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ora.Close)
	t.Setenv("PEER_ORA_URL", ora.URL)

	prevGate := authGate
	prevAuth := authEnforced
	t.Cleanup(func() {
		authGate = prevGate
		authEnforced = prevAuth
	})

	initAuthMode()
	setAuthEnforced(true)
	mux := http.NewServeMux()
	registerPeerSCMEventsMux(mux)
	return mux
}

func mintSCMEventToken(t *testing.T) string {
	t.Helper()
	tok, err := openauth.MintServiceJWTWithOrg(
		[]byte(testServiceSecret), "ora-api", "osa-api", "scm:events", "org-test", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestPeerSCMEventsTriggersOnLockfileChange(t *testing.T) {
	mux := newPeerSCMMux(t)
	body := map[string]interface{}{
		"event_type":      "pull_request",
		"organization_id": "org-test",
		"project_id":      "proj-test",
		"connector_id":    "conn-1",
		"repo_full_name":  "acme/app",
		"ref":             "refs/heads/feature",
		"pr_number":       42,
		"commit_sha":      "abc123",
		"scm_job_id":      "scm-1",
		"changed_paths":   []string{"src/main.go", "package-lock.json"},
		"dispatch":        false,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/peer/scm/events", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+mintSCMEventToken(t))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Checkers []peerCheckerResult `json:"checkers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Checkers) != 1 {
		t.Fatalf("checkers=%d want 1", len(out.Checkers))
	}
	c := out.Checkers[0]
	if !c.ShouldRun {
		t.Fatalf("should_run=false reason=%q", c.Reason)
	}
	if c.SecurityRunID == "" {
		t.Fatal("expected security_run_id")
	}
	if c.Status != "queued" {
		t.Fatalf("status=%q want queued", c.Status)
	}
}

func TestPeerSCMEventsSkipsWithoutLockfile(t *testing.T) {
	mux := newPeerSCMMux(t)
	body := map[string]interface{}{
		"event_type":     "pull_request",
		"connector_id":   "conn-1",
		"repo_full_name": "acme/app",
		"changed_paths":  []string{"README.md"},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/peer/scm/events", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+mintSCMEventToken(t))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var out struct {
		Checkers []peerCheckerResult `json:"checkers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Checkers[0].ShouldRun {
		t.Fatalf("expected should_run=false, reason=%q", out.Checkers[0].Reason)
	}
}

func TestPeerSCMEventsAcceptsPushDefault(t *testing.T) {
	body := peerSCMEventBody{
		EventType: "push.default", ConnectorID: "c", RepoFullName: "o/r",
		ChangedPaths: []string{"yarn.lock"},
	}
	res := evaluateDependenciesChecker(body)
	if !res.ShouldRun {
		t.Fatalf("push.default should run: %q", res.Reason)
	}
}

func TestPeerSCMEventsRejectsWrongScope(t *testing.T) {
	mux := newPeerSCMMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/peer/scm/events", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+mintPeerToken(t, "findings:read"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth failure, got %d", rr.Code)
	}
}

func TestNormalizeSecurityScannersCVE(t *testing.T) {
	got := normalizeSecurityScanners([]string{"dependencies", "OSV", "cve"})
	if len(got) != 1 || got[0] != "cve" {
		t.Fatalf("got %v", got)
	}
}
