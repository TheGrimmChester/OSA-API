package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsDependencyLockPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"package-lock.json", true},
		{"frontend/package-lock.json", true},
		{"requirements-prod.txt", true},
		{"requirements.txt", true},
		{"package.json", false},
		{"composer.json", false},
		{"go.mod", false},
	} {
		if got := isDependencyLockPath(tc.path); got != tc.want {
			t.Fatalf("isDependencyLockPath(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestChangedPathsHaveLockfile(t *testing.T) {
	ok, name := changedPathsHaveLockfile([]string{"src/main.go", "yarn.lock"})
	if !ok || name != "yarn.lock" {
		t.Fatalf("got ok=%v name=%q", ok, name)
	}
	ok, _ = changedPathsHaveLockfile([]string{"README.md"})
	if ok {
		t.Fatal("expected false for non-lockfile paths")
	}
}

func TestCollectLockfileDepsIgnoresManifests(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"lodash":"^4.17.21"}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"require":{"symfony/http-foundation":"^6.4"}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\nrequire github.com/gorilla/mux v1.8.0\n"), 0o644)

	deps, err := collectLockfileDeps(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("manifest-only tree produced %d deps, want 0", len(deps))
	}
}

func TestParsePackageLockV3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	raw := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "demo"},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/chalk": {"version": "5.3.0", "dev": true}
	  }
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := parsePackageLock(path, "package-lock.json")
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2", len(deps))
	}
}

func TestParseYarnLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	raw := `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := parseYarnLock(path, "yarn.lock")
	if len(deps) != 1 || deps[0].Package != "lodash" || deps[0].Version != "4.17.21" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}

func TestParseComposerLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "composer.lock")
	raw := `{"packages":[{"name":"symfony/http-foundation","version":"v6.4.0"}],"packages-dev":[]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := parseComposerLock(path, "composer.lock")
	if len(deps) != 1 || deps[0].Package != "symfony/http-foundation" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}

func TestParseRequirementsPinsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	raw := "requests==2.31.0\nDjango>=4.0\n# comment\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := parseRequirementsPinFile(path, "requirements.txt")
	if len(deps) != 1 || deps[0].Package != "requests" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}

func TestParseGoSum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	raw := "github.com/gorilla/mux v1.8.0 h1:abc\n" +
		"github.com/gorilla/mux v1.8.0/go.mod h1:def\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := parseGoSum(path, "go.sum")
	if len(deps) != 1 || deps[0].Package != "github.com/gorilla/mux" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}

func TestCollectLockfileDepsMixedTree(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
	  "lockfileVersion": 3,
	  "packages": {"node_modules/left-pad": {"version": "1.0.0"}}
	}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pillow==10.0.1\n"), 0o644)

	deps, err := collectLockfileDeps(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2", len(deps))
	}
}

func TestWorkspaceHasLockfiles(t *testing.T) {
	dir := t.TempDir()
	if workspaceHasLockfiles(dir) {
		t.Fatal("empty dir should not have lockfiles")
	}
	_ = os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: 5.4\n"), 0o644)
	if !workspaceHasLockfiles(dir) {
		t.Fatal("expected lockfile detection")
	}
}
