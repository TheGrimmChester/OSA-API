package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// lockfileDep is one pinned package/version from a lockfile. Manifests
// (package.json, composer.json, go.mod) are never parsed for CVE matching.
type lockfileDep struct {
	Package   string
	Version   string
	Ecosystem string // npm, pypi, composer, go — normalized before OSV query
	Manifest  string // relative lockfile path
	Scope     string // direct, dev, unknown
	Depth     uint8
}

var dependencyLockBasenames = map[string]string{
	"package-lock.json": "npm",
	"yarn.lock":         "npm",
	"pnpm-lock.yaml":    "npm",
	"composer.lock":     "composer",
	"poetry.lock":       "pypi",
	"Pipfile.lock":      "pypi",
	"go.sum":            "go",
}

var pnpmPkgKeyRE = regexp.MustCompile(`^\s{2}/(?:@([^/]+)/([^/@]+)|([^/@]+))/([^:]+):`)
var poetryPkgRE = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
var poetryVerRE = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)
var reqPinRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)`)

// isDependencyLockPath reports whether path names a dependency lockfile.
func isDependencyLockPath(path string) bool {
	base := filepath.Base(strings.TrimSpace(path))
	if _, ok := dependencyLockBasenames[base]; ok {
		return true
	}
	lower := strings.ToLower(base)
	return strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt")
}

// changedPathsHaveLockfile returns true when any changed path is a lockfile.
func changedPathsHaveLockfile(paths []string) (bool, string) {
	for _, p := range paths {
		if isDependencyLockPath(p) {
			return true, filepath.Base(p)
		}
	}
	return false, ""
}

// collectLockfileDeps walks root for lockfiles only and returns pinned deps.
func collectLockfileDeps(root string) ([]lockfileDep, error) {
	root = filepath.Clean(root)
	var out []lockfileDep
	seen := map[string]bool{}
	add := func(d lockfileDep) {
		if d.Package == "" || d.Version == "" || d.Ecosystem == "" {
			return
		}
		d.Package = strings.TrimSpace(d.Package)
		d.Version = strings.TrimSpace(strings.TrimPrefix(d.Version, "v"))
		key := strings.ToLower(d.Ecosystem) + "|" + d.Package + "|" + d.Version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, d)
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			if d != nil && d.IsDir() && scanSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			rel = base
		}
		eco, ok := dependencyLockBasenames[base]
		if !ok {
			lower := strings.ToLower(base)
			if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
				for _, dep := range parseRequirementsPinFile(path, rel) {
					add(dep)
				}
			}
			return nil
		}
		switch base {
		case "package-lock.json":
			for _, dep := range parsePackageLock(path, rel) {
				add(dep)
			}
		case "yarn.lock":
			for _, dep := range parseYarnLock(path, rel) {
				add(dep)
			}
		case "pnpm-lock.yaml":
			for _, dep := range parsePnpmLock(path, rel) {
				add(dep)
			}
		case "composer.lock":
			for _, dep := range parseComposerLock(path, rel) {
				add(dep)
			}
		case "poetry.lock":
			for _, dep := range parsePoetryLock(path, rel) {
				add(dep)
			}
		case "Pipfile.lock":
			for _, dep := range parsePipfileLock(path, rel) {
				add(dep)
			}
		case "go.sum":
			for _, dep := range parseGoSum(path, rel) {
				add(dep)
			}
		default:
			_ = eco
		}
		return nil
	})
	if len(out) > 5000 {
		out = out[:5000]
	}
	return out, nil
}

func parsePackageLock(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var body struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	var out []lockfileDep
	if len(body.Packages) > 0 {
		for name, pkg := range body.Packages {
			if name == "" || strings.HasPrefix(name, "node_modules/") && strings.Count(name, "node_modules/") > 1 {
				// keep nested node_modules entries — they are pinned versions
			}
			if name == "" {
				continue
			}
			pkgName := name
			if strings.HasPrefix(pkgName, "node_modules/") {
				pkgName = strings.TrimPrefix(pkgName, "node_modules/")
			}
			if pkgName == "" || pkg.Version == "" {
				continue
			}
			scope := "direct"
			if pkg.Dev {
				scope = "dev"
			}
			out = append(out, lockfileDep{
				Package: pkgName, Version: pkg.Version, Ecosystem: "npm",
				Manifest: rel, Scope: scope,
			})
		}
		return out
	}
	for name, pkg := range body.Dependencies {
		if name == "" || pkg.Version == "" {
			continue
		}
		scope := "direct"
		if pkg.Dev {
			scope = "dev"
		}
		out = append(out, lockfileDep{
			Package: name, Version: pkg.Version, Ecosystem: "npm",
			Manifest: rel, Scope: scope,
		})
	}
	return out
}

func parseYarnLock(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []lockfileDep
	lines := strings.Split(string(raw), "\n")
	var curPkg string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if strings.HasSuffix(trim, ":") && strings.Contains(trim, "@") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			curPkg = strings.TrimSuffix(trim, ":")
			curPkg = strings.Trim(curPkg, `"`)
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "version ") && curPkg != "" {
			ver := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "version")), `"`)
			name := curPkg
			if i := strings.LastIndex(name, "@"); i > 0 {
				name = name[:i]
			}
			if name != "" && ver != "" {
				out = append(out, lockfileDep{
					Package: name, Version: ver, Ecosystem: "npm",
					Manifest: rel, Scope: "unknown",
				})
			}
			curPkg = ""
		}
	}
	return out
}

func parsePnpmLock(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []lockfileDep
	inPackages := false
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && trim != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if strings.HasSuffix(trim, ":") && !strings.Contains(trim, "/") {
				break
			}
		}
		if !inPackages {
			continue
		}
		if m := pnpmPkgKeyRE.FindStringSubmatch(line); len(m) == 5 {
			var name string
			if m[1] != "" {
				name = "@" + m[1] + "/" + m[2]
			} else {
				name = m[3]
			}
			ver := m[4]
			if name != "" && ver != "" {
				out = append(out, lockfileDep{
					Package: name, Version: ver, Ecosystem: "npm",
					Manifest: rel, Scope: "unknown",
				})
			}
		}
	}
	return out
}

func parseComposerLock(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var body struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	var out []lockfileDep
	for _, pkg := range body.Packages {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, lockfileDep{
			Package: pkg.Name, Version: strings.TrimPrefix(pkg.Version, "v"), Ecosystem: "composer",
			Manifest: rel, Scope: "direct",
		})
	}
	for _, pkg := range body.PackagesDev {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, lockfileDep{
			Package: pkg.Name, Version: strings.TrimPrefix(pkg.Version, "v"), Ecosystem: "composer",
			Manifest: rel, Scope: "dev",
		})
	}
	return out
}

func parsePoetryLock(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(raw)
	names := poetryPkgRE.FindAllStringSubmatch(text, -1)
	vers := poetryVerRE.FindAllStringSubmatch(text, -1)
	var out []lockfileDep
	for i := 0; i < len(names) && i < len(vers); i++ {
		name := names[i][1]
		ver := vers[i][1]
		if name == "" || ver == "" {
			continue
		}
		out = append(out, lockfileDep{
			Package: name, Version: ver, Ecosystem: "pypi",
			Manifest: rel, Scope: "unknown",
		})
	}
	return out
}

func parsePipfileLock(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var body map[string]map[string]map[string]interface{}
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	var out []lockfileDep
	for section, scope := range map[string]string{"default": "direct", "develop": "dev"} {
		pkgs, ok := body[section]
		if !ok {
			continue
		}
		for name, meta := range pkgs {
			if name == "" || meta == nil {
				continue
			}
			ver := fmt.Sprint(meta["version"])
			ver = strings.TrimPrefix(strings.TrimSpace(ver), "==")
			if ver == "" || ver == "<nil>" {
				continue
			}
			out = append(out, lockfileDep{
				Package: name, Version: ver, Ecosystem: "pypi",
				Manifest: rel, Scope: scope,
			})
		}
	}
	return out
}

func parseGoSum(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []lockfileDep
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if strings.Contains(parts[1], "/go.mod") {
			continue
		}
		mod, ver := parts[0], strings.TrimPrefix(parts[1], "v")
		key := mod + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, lockfileDep{
			Package: mod, Version: ver, Ecosystem: "go",
			Manifest: rel, Scope: "unknown",
		})
	}
	return out
}

func parseRequirementsPinFile(path, rel string) []lockfileDep {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []lockfileDep
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqPinRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		out = append(out, lockfileDep{
			Package: m[1], Version: strings.Trim(m[2], `"`), Ecosystem: "pypi",
			Manifest: rel, Scope: "direct",
		})
	}
	return out
}

func workspaceHasLockfiles(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			if d != nil && d.IsDir() && scanSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if isDependencyLockPath(path) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
