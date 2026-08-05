package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
)

// registerHubGitHubMux exposes hub tenancy + ORA GitHub connector discovery for the dashboard.
// Credentials stay in ORA; hub provides identity/org directory only.
func registerHubGitHubMux(mux *http.ServeMux, authView func(string, http.HandlerFunc)) {
	authView("/api/hub/organizations", handleHubOrganizations)
	authView("/api/oam/projects", handleOAMProjects)
	authView("/api/hub/github/status", handleHubGitHubStatus)
	authView("/api/github/connectors", handleGitHubConnectorsProxy)
	mux.HandleFunc("/api/github/connectors/", func(w http.ResponseWriter, r *http.Request) {
		h := handleGitHubConnectorSub
		if authRequiredEnv() {
			AuthMiddleware(h, "viewer")(w, r)
			return
		}
		h(w, r)
	})
	authView("/api/security/targets", handleSecurityTargets)
}

func peerOPAURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("PEER_OPA_URL")), "/")
}

func peerORAURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("PEER_ORA_URL")), "/")
}

func peerOAMURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("PEER_OAM_URL")), "/")
}

func handleHubOrganizations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	base := peerOPAURL()
	if base == "" {
		writeJSON(w, map[string]interface{}{
			"organizations":    []interface{}{},
			"peer_unavailable": true,
			"peer":             "opa-hub",
			"note":             "Set PEER_OPA_URL to discover hub organizations.",
		})
		return
	}
	raw, status, err := proxyPeerGET(r.Context(), base+"/api/tenancy/organizations", r)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"organizations": []interface{}{},
			"error":         err.Error(),
			"peer":          "opa-hub",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(aliasDirectoryIDs(raw, "organizations", "org_id"))
}

// handleOAMProjects proxies the OAM project directory for the dashboard's tenant
// picker.
//
// Organizations come from the hub because the hub owns that directory for peers
// (see OPA-Hub internal/oamdir), but neither the hub nor OSA serves a projects
// route, so this one reads OAM directly — the same PEER_OAM_URL the hub and OPM
// already use. Unset, the picker stays empty instead of failing, mirroring
// handleHubOrganizations.
func handleOAMProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	base := peerOAMURL()
	if base == "" {
		writeJSON(w, map[string]interface{}{
			"projects":         []interface{}{},
			"peer_unavailable": true,
			"peer":             "oam-api",
			"note":             "Set PEER_OAM_URL to discover projects.",
		})
		return
	}
	target := base + "/api/projects"
	// "all" is the tenant-header sentinel for unscoped, not an org id. OAM's
	// organization_id filter is a concrete-id predicate, so forwarding the
	// sentinel would emit `organization_id = 'all'` and empty the picker on the
	// very selection that is meant to widen it. Omitting it lets OAM scope by
	// actor instead.
	if org := strings.TrimSpace(r.URL.Query().Get("organization_id")); org != "" && !strings.EqualFold(org, "all") {
		target += "?organization_id=" + url.QueryEscape(org)
	}
	raw, status, err := proxyPeerGET(r.Context(), target, r)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"projects": []interface{}{},
			"error":    err.Error(),
			"peer":     "oam-api",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(aliasDirectoryIDs(raw, "projects", "project_id"))
}

// aliasDirectoryIDs adds the dashboard's field name to each row of a proxied
// directory payload.
//
// OAM and the hub both key directory rows as "id"; the OSA dashboard's tenant
// picker reads "org_id"/"project_id" (shell/Shell.jsx, pages/Account.jsx). Doing
// this here keeps family-shape knowledge out of the dashboard, and *adding* the
// alias rather than renaming leaves the documented "id" field intact — OPM's
// dashboard reads `id` off its own /api/hub/organizations.
//
// A body that does not parse as the expected shape is returned untouched: peer
// error bodies are not always JSON, and rewriting one would hide the real
// failure behind a decode error.
func aliasDirectoryIDs(raw []byte, listKey, aliasKey string) []byte {
	var payload map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay json.Number so a re-encode cannot reformat one (a float64
	// round-trip would turn a large id or timestamp into scientific notation).
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return raw
	}
	list, ok := payload[listKey].([]interface{})
	if !ok {
		return raw
	}
	for _, item := range list {
		row, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if _, exists := row[aliasKey]; exists {
			continue
		}
		if id, ok := row["id"].(string); ok && id != "" {
			row[aliasKey] = id
		}
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return raw
	}
	return out
}

func handleHubGitHubStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	base := peerOPAURL()
	out := map[string]interface{}{
		"credentials_home":    "ora",
		"peer_opa_url":        base,
		"peer_ora_url":        peerORAURL(),
		"peer_opa_configured": base != "",
		"peer_ora_configured": peerORAURL() != "",
		"hub_role":            "identity_and_tenancy",
		"note":                "Connect GitHub App or PAT in ORA. OSA discovers orgs via hub and repos via ORA connectors; scans use ephemeral clones.",
	}
	if base != "" {
		raw, status, err := proxyPeerGET(r.Context(), base+"/api/github/status", r)
		if err == nil && status < 300 {
			var hub map[string]interface{}
			if json.Unmarshal(raw, &hub) == nil {
				for k, v := range hub {
					out[k] = v
				}
			}
		}
	}
	writeJSON(w, out)
}

func handleSecurityTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	writeJSON(w, map[string]interface{}{
		"model":               "hub_org_ora_github",
		"primary":             "owner/repo via ORA connectors",
		"credentials_home":    "ora",
		"peer_opa_configured": peerOPAURL() != "",
		"peer_ora_configured": peerORAURL() != "",
		"peer_oam_configured": peerOAMURL() != "",
		"endpoints": map[string]string{
			"organizations": "/api/hub/organizations",
			"projects":      "/api/oam/projects",
			"github_status": "/api/hub/github/status",
			"connectors":    "/api/github/connectors",
			"repos":         "/api/github/connectors/{id}/repos",
		},
		"scan": map[string]string{
			"create": "POST /api/security/runs with connector_id + repo_full_name (owner/repo)",
			"clone":  "Ephemeral tmp clone via ORA POST /api/peer/scm/clone-credentials; cleaned after scan",
		},
		"note": "Durable local workspace mounts are not the primary UX. Prefer GitHub-linked repos discovered through hub tenancy + ORA connectors.",
	})
}

func handleGitHubConnectorsProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	base := peerORAURL()
	if base == "" {
		writeJSON(w, map[string]interface{}{
			"connectors":       []interface{}{},
			"peer_unavailable": true,
			"peer":             "ora-api",
			"note":             "Set PEER_ORA_URL. Connect GitHub App or PAT in ORA.",
		})
		return
	}
	raw, status, err := proxyPeerGET(r.Context(), base+"/api/connectors", r)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"connectors": []interface{}{},
			"error":      err.Error(),
			"peer":       "ora-api",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func handleGitHubConnectorSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/github/connectors/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "repos" {
		http.Error(w, "not found", 404)
		return
	}
	id := parts[0]
	base := peerORAURL()
	if base == "" {
		writeJSON(w, map[string]interface{}{
			"repos":            []interface{}{},
			"peer_unavailable": true,
			"peer":             "ora-api",
		})
		return
	}
	raw, status, err := proxyPeerGET(r.Context(), base+"/api/connectors/"+id+"/repos", r)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"repos": []interface{}{},
			"error": err.Error(),
			"peer":  "ora-api",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// proxyPeerGET forwards the caller's Authorization and tenant headers to a peer.
// Used for hub tenancy and ORA connector reads (shared user JWT in co-deployed mode).
func proxyPeerGET(ctx context.Context, url string, r *http.Request) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	} else if c, err := r.Cookie(authCookieName); err == nil && c.Value != "" {
		req.Header.Set("Authorization", "Bearer "+c.Value)
	}
	for _, h := range []string{"X-Organization-ID", "X-Project-ID"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	// Drain before closing so the connection can be reused: the LimitReader stops
	// at 8 MiB and a read error stops sooner, and closing a body with bytes still
	// pending makes net/http discard the connection instead of returning it to the
	// keep-alive pool. Same pattern as the ClickHouse writer.
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

type cloneCredentials struct {
	OK           bool   `json:"ok"`
	Token        string `json:"token"`
	CloneURL     string `json:"clone_url"`
	RepoFullName string `json:"repo_full_name"`
	ExpiresAt    string `json:"expires_at"`
}

// requestORACloneCredentials mints a service JWT and asks ORA for a short-lived clone token.
func requestORACloneCredentials(ctx context.Context, connectorID, repoFullName, orgID string) (*cloneCredentials, error) {
	cfg := openclient.PeerFromEnv("PEER_ORA_URL", "osa-api", "ora-api", "scm:clone health:read")
	cfg.OrgID = orgID
	var out cloneCredentials
	err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/peer/scm/clone-credentials", map[string]string{
		"connector_id":   connectorID,
		"repo_full_name": repoFullName,
	}, &out)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.Token) == "" {
		return nil, fmt.Errorf("ora returned empty clone token")
	}
	if out.CloneURL == "" {
		out.CloneURL = "https://github.com/" + repoFullName + ".git"
	}
	return &out, nil
}

// ephemeralClone checks out owner/repo into a temp directory and returns the path.
// Caller must RemoveAll when finished.
func ephemeralClone(ctx context.Context, connectorID, repoFullName, ref, orgID string) (string, error) {
	repoFullName = strings.TrimSpace(repoFullName)
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" || repoFullName == "" || !strings.Contains(repoFullName, "/") {
		return "", fmt.Errorf("connector_id and repo_full_name (owner/repo) required")
	}
	creds, err := requestORACloneCredentials(ctx, connectorID, repoFullName, orgID)
	if err != nil {
		return "", fmt.Errorf("clone credentials: %w", err)
	}
	dir, err := os.MkdirTemp("", "osa-scan-*")
	if err != nil {
		return "", err
	}
	safeName := strings.ReplaceAll(repoFullName, "/", "_")
	dest := filepath.Join(dir, safeName)
	authURL := authenticatedCloneURL(creds.CloneURL, creds.Token)
	args := []string{"clone", "--depth", "1"}
	if ref = strings.TrimSpace(ref); ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, authURL, dest)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dir)
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		msg = strings.ReplaceAll(msg, creds.Token, "***")
		return "", fmt.Errorf("git clone: %s", truncateStr(msg, 400))
	}
	return dest, nil
}

func authenticatedCloneURL(cloneURL, token string) string {
	u := strings.TrimSpace(cloneURL)
	tok := strings.TrimSpace(token)
	if tok == "" {
		return u
	}
	if strings.HasPrefix(u, "https://") {
		rest := strings.TrimPrefix(u, "https://")
		if at := strings.Index(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return "https://x-access-token:" + tok + "@" + rest
	}
	return u
}
