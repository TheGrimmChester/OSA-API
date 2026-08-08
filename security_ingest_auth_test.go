package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSecurityIngestFailsClosedUnderAuthWhenTokenUnset(t *testing.T) {
	prevTok := os.Getenv("OSA_SECURITY_INGEST_TOKEN")
	prevOIDC := os.Getenv("OPA_SECURITY_OIDC_REQUIRE")
	t.Cleanup(func() {
		_ = os.Setenv("OSA_SECURITY_INGEST_TOKEN", prevTok)
		_ = os.Setenv("OPA_SECURITY_OIDC_REQUIRE", prevOIDC)
	})
	_ = os.Unsetenv("OSA_SECURITY_INGEST_TOKEN")
	_ = os.Setenv("OPA_SECURITY_OIDC_REQUIRE", "0")

	setAuthEnforced(true)
	t.Cleanup(func() { setAuthEnforced(false) })
	req := httptest.NewRequest(http.MethodPost, "/v1/sbom", nil)
	if securityIngestAuthorized(req) {
		t.Fatal("auth on + empty ingest token must fail closed")
	}

	setAuthEnforced(false)
	if !securityIngestAuthorized(req) {
		t.Fatal("lab posture (auth off, no token) may stay open")
	}
}

func TestEvaluateScopedGateFiltersByOrg(t *testing.T) {
	setAuthEnforced(true)
	t.Cleanup(func() { setAuthEnforced(false) })

	out := evaluateScopedGate("", "", "srun-x", "high")
	if out["fail"] != true {
		t.Fatalf("empty org under auth must fail closed, got %#v", out)
	}

	// No queryClient → no CH rows; live map empty → pass with org stamped.
	out2 := evaluateScopedGate("nas", "proj", "srun-missing", "high")
	if out2["organization_id"] != "nas" {
		t.Fatalf("want organization_id nas, got %#v", out2)
	}
	if out2["project_id"] != "proj" {
		t.Fatalf("want project_id proj, got %#v", out2)
	}
}

func TestSecurityGateRequiresOrgUnderAuth(t *testing.T) {
	setAuthEnforced(true)
	t.Cleanup(func() { setAuthEnforced(false) })

	out := evaluateScopedGate("", "proj", "srun-need-org", "high")
	if out["fail"] != true {
		t.Fatalf("evaluateScopedGate empty org must fail, got %#v", out)
	}
	reasons, _ := out["reasons"].([]string)
	joined := strings.Join(reasons, " ")
	if !strings.Contains(joined, "organization required") {
		t.Fatalf("want organization required reason, got %#v", out)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/security/gate?security_run_id=srun-need-org&min_severity=high", nil)
	rr := httptest.NewRecorder()
	handleSecurityGate(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty org under auth want 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "X-Organization-ID") {
		t.Fatalf("400 body should mention org header, got %q", rr.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/security/gate?security_run_id=srun-need-org", nil)
	req2.Header.Set("X-Organization-ID", "nas")
	req2.Header.Set("X-Project-ID", "infra")
	rr2 := httptest.NewRecorder()
	handleSecurityGate(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("concrete org should evaluate: code=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestEvaluateScopedGateForeignOrg(t *testing.T) {
	setAuthEnforced(true)
	t.Cleanup(func() { setAuthEnforced(false) })

	runID := "srun-foreign-idor"
	rememberSecurityRun(map[string]interface{}{
		"id": runID, "organization_id": "other", "project_id": "infra",
		"summary_json": `{"counts":{"secrets":3},"severity_counts":{"secrets":{"critical":2,"high":1}}}`,
	})
	t.Cleanup(func() { securityRunLive.Delete(runID) })

	out := evaluateScopedGate("nas", "infra", runID, "high")
	if out["fail"] != true {
		t.Fatalf("foreign org run must fail closed, not pass: %#v", out)
	}
	reasons, _ := out["reasons"].([]string)
	joined := strings.Join(reasons, " ")
	if strings.Contains(joined, "secret findings") || strings.Contains(joined, "live") {
		t.Fatalf("must not leak foreign findings into reasons: %#v", out)
	}
	if !strings.Contains(joined, "organization scope") {
		t.Fatalf("want scope denial reason, got %#v", out)
	}
	if out["organization_id"] != "nas" {
		t.Fatalf("response org must be caller scope, got %#v", out["organization_id"])
	}
}

func TestTenantScopeSQLEmptyOrgUnderAuth(t *testing.T) {
	setAuthEnforced(true)
	t.Cleanup(func() { setAuthEnforced(false) })

	req := httptest.NewRequest(http.MethodGet, "/api/vulns/findings", nil)
	got := tenantScopeSQL(req, nil, "")
	if got != " AND (1=0)" {
		t.Fatalf("empty org under auth want AND (1=0), got %q", got)
	}
	if strings.Contains(got, "default-org") {
		t.Fatalf("must never invent default-org, got %q", got)
	}

	all := httptest.NewRequest(http.MethodGet, "/api/vulns/findings", nil)
	all.Header.Set("X-Organization-ID", "all")
	all.Header.Set("X-Project-ID", "all")
	gotAll := tenantScopeSQL(all, nil, "")
	if gotAll != " AND (1=0)" {
		t.Fatalf("all/all under auth want AND (1=0), got %q", gotAll)
	}
	if strings.Contains(gotAll, "default-org") {
		t.Fatalf("all marker must not invent default-org, got %q", gotAll)
	}

	nas := httptest.NewRequest(http.MethodGet, "/api/vulns/findings", nil)
	nas.Header.Set("X-Organization-ID", "nas")
	nas.Header.Set("X-Project-ID", "infra")
	gotNas := tenantScopeSQL(nas, nil, "")
	if gotNas == "" || gotNas == " AND (1=0)" {
		t.Fatalf("concrete org must scope positively, got %q", gotNas)
	}
	if !strings.Contains(gotNas, "nas") {
		t.Fatalf("want nas in scope SQL, got %q", gotNas)
	}
}
