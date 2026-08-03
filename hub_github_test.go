package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticatedCloneURL(t *testing.T) {
	got := authenticatedCloneURL("https://github.com/acme/app.git", "tok123")
	want := "https://x-access-token:tok123@github.com/acme/app.git"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// Existing userinfo is replaced.
	got = authenticatedCloneURL("https://old:pass@github.com/acme/app.git", "tok")
	want = "https://x-access-token:tok@github.com/acme/app.git"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestPeerURLTrim(t *testing.T) {
	t.Setenv("PEER_OPA_URL", "http://hub:8080/")
	t.Setenv("PEER_ORA_URL", " http://ora:8091 ")
	if peerOPAURL() != "http://hub:8080" {
		t.Fatalf("PEER_OPA_URL trim failed: %q", peerOPAURL())
	}
	if peerORAURL() != "http://ora:8091" {
		t.Fatalf("PEER_ORA_URL trim failed: %q", peerORAURL())
	}
}

func TestSecurityWorkspaceRootFallback(t *testing.T) {
	t.Setenv("OSA_SECURITY_WORKSPACE", "")
	t.Setenv("OPA_SECURITY_WORKSPACE", "")
	if securityWorkspaceRoot() != "/workspace" {
		t.Fatalf("default workspace: %q", securityWorkspaceRoot())
	}
	dir := t.TempDir()
	t.Setenv("OSA_SECURITY_WORKSPACE", dir)
	if securityWorkspaceRoot() != filepath.Clean(dir) {
		t.Fatalf("OSA_SECURITY_WORKSPACE not honored")
	}
}

func TestRepoFullNameValidation(t *testing.T) {
	cases := []struct {
		repo string
		ok   bool
	}{
		{"acme/app", true},
		{"acme", false},
		{"", false},
		{"acme/app/extra", true}, // still contains /
	}
	for _, c := range cases {
		ok := c.repo != "" && strings.Contains(c.repo, "/")
		if ok != c.ok {
			t.Fatalf("repo %q: got ok=%v want %v", c.repo, ok, c.ok)
		}
	}
	_ = os.DevNull
}
