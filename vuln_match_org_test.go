package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVulnMatchRequiresOrganization(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/vulns/match", nil)
	rec := httptest.NewRecorder()
	handleVulnMatch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty org: got %d want 400 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMatchAdvisoriesForServiceEmptyOrgReturnsZero(t *testing.T) {
	if n := matchAdvisoriesForService("", "", "", "", ""); n != 0 {
		t.Fatalf("empty org: got %d want 0", n)
	}
	if n := matchAdvisoriesForService("all", "", "", "", ""); n != 0 {
		t.Fatalf("all org: got %d want 0", n)
	}
}
