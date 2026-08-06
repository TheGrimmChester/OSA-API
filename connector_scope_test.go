package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectorActiveUnderOrg(t *testing.T) {
	cases := []struct {
		name string
		row  map[string]interface{}
		org  string
		ok   bool
	}{
		{"active own org", map[string]interface{}{"id": "c1", "status": "active", "organization_id": "nas"}, "nas", true},
		{"legacy empty status fails closed", map[string]interface{}{"id": "c1", "organization_id": "nas"}, "nas", false},
		{"pending_claim", map[string]interface{}{"id": "c1", "status": "pending_claim", "organization_id": ""}, "nas", false},
		{"pending with org stamped wrongly", map[string]interface{}{"id": "c1", "status": "pending_claim", "organization_id": "nas"}, "nas", false},
		{"foreign org", map[string]interface{}{"id": "c1", "status": "active", "organization_id": "other"}, "nas", false},
		{"empty org on connector", map[string]interface{}{"id": "c1", "status": "active", "organization_id": ""}, "nas", false},
		{"empty request org", map[string]interface{}{"id": "c1", "status": "active", "organization_id": "nas"}, "", false},
		{"all request org", map[string]interface{}{"id": "c1", "status": "active", "organization_id": "nas"}, "all", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := connectorActiveUnderOrg(c.row, c.org)
			if got != c.ok {
				t.Fatalf("got %v want %v", got, c.ok)
			}
		})
	}
}

func TestFilterConnectorsForOrg(t *testing.T) {
	rows := []interface{}{
		map[string]interface{}{"id": "own", "status": "active", "organization_id": "nas"},
		map[string]interface{}{"id": "pending", "status": "pending_claim", "organization_id": ""},
		map[string]interface{}{"id": "foreign", "status": "active", "organization_id": "acme"},
		map[string]interface{}{"id": "empty-org-active", "status": "active", "organization_id": ""},
	}
	got := filterConnectorsForOrg(rows, "nas")
	if len(got) != 1 {
		t.Fatalf("len=%d want 1: %#v", len(got), got)
	}
	m := got[0].(map[string]interface{})
	if getString(m, "id") != "own" {
		t.Fatalf("id=%q", getString(m, "id"))
	}
}

func TestFilterConnectorsProxyBody(t *testing.T) {
	in := map[string]interface{}{
		"connectors": []interface{}{
			map[string]interface{}{"id": "own", "status": "active", "organization_id": "nas"},
			map[string]interface{}{"id": "pend", "status": "pending_claim", "organization_id": ""},
			map[string]interface{}{"id": "x", "status": "active", "organization_id": "other"},
		},
		"note": "keep",
	}
	raw, _ := json.Marshal(in)
	out := filterConnectorsProxyBody(raw, "nas")
	var payload map[string]interface{}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatal(err)
	}
	list, _ := payload["connectors"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("filtered len=%d", len(list))
	}
	if payload["note"] != "keep" {
		t.Fatalf("lost sibling field")
	}
	// Non-JSON passthrough
	if string(filterConnectorsProxyBody([]byte("not-json"), "nas")) != "not-json" {
		t.Fatalf("expected passthrough")
	}
}

func TestFindConnectorInList(t *testing.T) {
	rows := []interface{}{
		map[string]interface{}{"id": "a", "status": "active", "organization_id": "nas"},
		map[string]interface{}{"id": "b", "status": "active", "organization_id": "nas"},
	}
	if findConnectorInList(rows, "b") == nil {
		t.Fatal("expected b")
	}
	if findConnectorInList(rows, "missing") != nil {
		t.Fatal("expected nil")
	}
	if findConnectorInList(filterConnectorsForOrg(rows, "other"), "a") != nil {
		t.Fatal("foreign filter should drop a")
	}
}

func stubORAConnectorsList(t *testing.T, connectors []map[string]interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/connectors" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"connectors": connectors})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("PEER_ORA_URL", srv.URL)
	return srv
}

func TestVerifyConnectorActiveRejectsForeignAndPending(t *testing.T) {
	stubORAConnectorsList(t, []map[string]interface{}{
		{"id": "own", "status": "active", "organization_id": "nas"},
		{"id": "foreign", "status": "active", "organization_id": "other"},
		{"id": "pending", "status": "pending_claim", "organization_id": ""},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/security/runs", nil)
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")

	if msg, code := verifyConnectorActiveForRequest(req, "own"); msg != "" || code != 0 {
		t.Fatalf("own: msg=%q code=%d", msg, code)
	}
	if msg, code := verifyConnectorActiveForRequest(req, "foreign"); msg == "" || code != 403 {
		t.Fatalf("foreign: msg=%q code=%d want 403", msg, code)
	}
	if msg, code := verifyConnectorActiveForRequest(req, "pending"); msg == "" || code != 403 {
		t.Fatalf("pending: msg=%q code=%d want 403", msg, code)
	}
	if msg, code := verifyConnectorActiveForRequest(req, "missing"); msg == "" || code != 403 {
		t.Fatalf("missing: msg=%q code=%d want 403", msg, code)
	}
}

func TestCreateSecurityRunRejectsForeignConnector(t *testing.T) {
	stubORAConnectorsList(t, []map[string]interface{}{
		{"id": "foreign", "status": "active", "organization_id": "other"},
		{"id": "own", "status": "active", "organization_id": "nas"},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/security/runs", nil)
	req.Header.Set("X-Organization-ID", "nas")
	req.Header.Set("X-Project-ID", "infra")

	_, msg, code := createSecurityRun(req, securityRunCreateBody{
		ConnectorID:  "foreign",
		RepoFullName: "acme/app",
		Dispatch:     boolPtr(false),
	}, true)
	if code != 403 || msg == "" {
		t.Fatalf("foreign create: code=%d msg=%q want 403", code, msg)
	}

	row, msg, code := createSecurityRun(req, securityRunCreateBody{
		ConnectorID:  "own",
		RepoFullName: "acme/app",
		Dispatch:     boolPtr(false),
	}, true)
	if code != 200 || msg != "" || row == nil {
		t.Fatalf("own create: code=%d msg=%q row=%v", code, msg, row)
	}
}

func boolPtr(v bool) *bool { return &v }
