package main

import (
	"testing"
)

// cmpVersion is for ORDERING only — OSV decides vulnerability membership with the
// ecosystem's real rules. These tests cover the two jobs it actually has: picking
// the nearest fix, and displaying versions in order.

func TestCmpVersionOrdersNumericSegments(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.99.99", 1},
		// Missing segments are zero, so 1.2 == 1.2.0.
		{"1.2", "1.2.0", 0},
		{"1.2", "1.2.1", -1},
		// Unbounded segments. A fixed [3]int would truncate these into equality —
		// 1.2.3.4 and PyPI's 2024.1.1.1 are both real.
		{"1.2.3.4", "1.2.3.3", 1},
		{"1.2.3.4", "1.2.3", 1},
		{"2024.1.1.1", "2024.1.1.0", 1},
		{"2024.1.1.1", "2024.1.1.2", -1},
		// Double-digit segments must not compare as strings: "10" > "9".
		{"1.10.0", "1.9.0", 1},
		{"1.0.10", "1.0.9", 1},
		// Leading v and = are tolerated; they appear routinely in lockfiles.
		{"v1.2.3", "1.2.3", 0},
		{"=1.2.3", "1.2.3", 0},
		// Build metadata is not part of precedence (semver §10).
		{"1.2.3+build9", "1.2.3+build1", 0},
		{"1.2.3+build1", "1.2.3", 0},
	} {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			if got := cmpVersion(tc.a, tc.b); got != tc.want {
				t.Fatalf("cmpVersion(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
			}
			// Antisymmetry: a mistake here silently corrupts "nearest fix".
			if got := cmpVersion(tc.b, tc.a); got != -tc.want {
				t.Fatalf("cmpVersion(%q,%q)=%d want %d (not antisymmetric)", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

// semver §11: a version WITH a prerelease is LOWER than the same version without
// one. Backwards, `1.0.0-rc1` looks newer than `1.0.0` and a prerelease gets picked
// as the nearest fix — telling someone to upgrade to a release candidate.
func TestCmpVersionPrereleaseRanksBelowRelease(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		// Numeric identifiers compare numerically, not as strings.
		{"1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		// A numeric identifier ranks BELOW an alphanumeric one.
		{"1.0.0-1", "1.0.0-alpha", -1},
		// More fields win when all preceding ones are equal.
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		// A prerelease on a lower version is still lower overall.
		{"1.0.0-rc1", "0.9.9", 1},
		// PEP 440 style with no separator: 1.0rc1 < 1.0.
		{"1.0rc1", "1.0", -1},
	} {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			if got := cmpVersion(tc.a, tc.b); got != tc.want {
				t.Fatalf("cmpVersion(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// nearestFix must pick the NEAREST upgrade, not the newest release: telling someone
// on 4.17.20 to jump to 5.0.0 when 4.17.21 fixes it is bad advice.
func TestNearestFixPicksTheClosestUpgrade(t *testing.T) {
	ranges := []osvRange{{
		Type: "SEMVER",
		Events: []osvRangeEvent{
			{Introduced: "0"},
			{Fixed: "5.0.0"},
			{Fixed: "4.17.21"},
			{Fixed: "4.16.9"},
		},
	}}
	fixed, state := nearestFix(ranges, "4.17.20")
	if state != fixStateFixed {
		t.Fatalf("state=%q want %q", state, fixStateFixed)
	}
	if fixed != "4.17.21" {
		t.Fatalf("fixed=%q want 4.17.21 (nearest above the installed version)", fixed)
	}
}

// A fix at or below the installed version does not describe our version, so it is
// not an upgrade.
func TestNearestFixIgnoresFixesAtOrBelowInstalled(t *testing.T) {
	ranges := []osvRange{{
		Type:   "SEMVER",
		Events: []osvRangeEvent{{Introduced: "0"}, {Fixed: "1.0.0"}},
	}}
	fixed, state := nearestFix(ranges, "2.0.0")
	if fixed != "" {
		t.Fatalf("fixed=%q — a fix below the installed version is not an upgrade", fixed)
	}
	if state == fixStateFixed {
		t.Fatalf("state=%q must not claim a fix", state)
	}
}

// "upgrade to 4f3a9c…" is user-hostile and no package manager can act on it. But if
// GIT is the only range with a fix, that must be reported as its own state rather
// than as "no patch exists".
func TestGitOnlyFixIsReportedAsGitNotAsNoFix(t *testing.T) {
	ranges := []osvRange{{
		Type: "GIT",
		Events: []osvRangeEvent{
			{Introduced: "0"},
			{Fixed: "4f3a9c1d2e5b6a7890abcdef1234567890abcdef"},
		},
	}}
	fixed, state := nearestFix(ranges, "1.0.0")
	if fixed != "" {
		t.Fatalf("fixed=%q — a commit sha must not be reported as a version", fixed)
	}
	if state != fixStateGit {
		t.Fatalf("state=%q want %q", state, fixStateGit)
	}
}

// A SEMVER fix must be preferred even when a GIT range also carries one.
func TestSemverFixWinsOverGit(t *testing.T) {
	ranges := []osvRange{
		{Type: "GIT", Events: []osvRangeEvent{{Fixed: "deadbeefdeadbeefdeadbeefdeadbeef"}}},
		{Type: "SEMVER", Events: []osvRangeEvent{{Introduced: "0"}, {Fixed: "1.2.4"}}},
	}
	fixed, state := nearestFix(ranges, "1.2.3")
	if fixed != "1.2.4" || state != fixStateFixed {
		t.Fatalf("fixed=%q state=%q want 1.2.4/fixed", fixed, state)
	}
}

// last_affected with no fixed is the advisory saying plainly that nothing has been
// released. That is different from "we do not know", and the gate treats them
// differently.
func TestLastAffectedWithNoFixIsStateNone(t *testing.T) {
	ranges := []osvRange{{
		Type:   "SEMVER",
		Events: []osvRangeEvent{{Introduced: "0"}, {LastAffected: "3.1.4"}},
	}}
	fixed, state := nearestFix(ranges, "3.1.0")
	if fixed != "" || state != fixStateNone {
		t.Fatalf("fixed=%q state=%q want ''/none", fixed, state)
	}
}

// No ranges at all means the advisory said nothing usable — `unknown`, not `none`.
// Conflating them would let the gate treat "we do not know" as "no patch exists".
func TestNoRangesIsUnknownNotNone(t *testing.T) {
	fixed, state := nearestFix(nil, "1.0.0")
	if fixed != "" || state != fixStateUnknown {
		t.Fatalf("fixed=%q state=%q want ''/unknown", fixed, state)
	}
}

func TestIntroducedVersionSkipsZeroAndGit(t *testing.T) {
	ranges := []osvRange{
		{Type: "GIT", Events: []osvRangeEvent{{Introduced: "abc123"}}},
		{Type: "SEMVER", Events: []osvRangeEvent{{Introduced: "0"}}},
		{Type: "SEMVER", Events: []osvRangeEvent{{Introduced: "2.1.0"}, {Introduced: "1.5.0"}}},
	}
	if got := introducedVersion(ranges); got != "1.5.0" {
		t.Fatalf("introducedVersion=%q want 1.5.0 (lowest non-zero, non-GIT)", got)
	}
	// "0" alone means "from the beginning" and is not worth displaying.
	if got := introducedVersion([]osvRange{{Type: "SEMVER", Events: []osvRangeEvent{{Introduced: "0"}}}}); got != "" {
		t.Fatalf("introducedVersion=%q want empty for a bare 0", got)
	}
}

// Malformed input must not panic. Version strings arrive from lockfiles and
// advisories, both of which contain surprises.
func TestCmpVersionSurvivesJunk(t *testing.T) {
	junk := []string{"", "   ", "v", "-", "...", "1..2", "abc", "1.2.3-", "+build", "∞", "1.2.3.4.5.6.7.8"}
	for _, a := range junk {
		for _, b := range junk {
			_ = cmpVersion(a, b) // must not panic
		}
		_ = cmpVersion(a, "1.2.3")
		_ = cmpVersion("1.2.3", a)
	}
	// An empty installed version must not make every fix look like an upgrade
	// *incorrectly* — it should accept the lowest fix, since we cannot compare.
	ranges := []osvRange{{Type: "SEMVER", Events: []osvRangeEvent{{Fixed: "2.0.0"}, {Fixed: "1.0.0"}}}}
	fixed, state := nearestFix(ranges, "")
	if state != fixStateFixed || fixed != "1.0.0" {
		t.Fatalf("fixed=%q state=%q want 1.0.0/fixed", fixed, state)
	}
}

// Sanity: ordering must be transitive over a realistic ladder, since nearestFix
// relies on repeated pairwise comparison.
func TestOrderingIsTransitiveOverARealisticLadder(t *testing.T) {
	ladder := []string{
		"0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc1",
		"1.0.0", "1.0.1", "1.1.0", "1.10.0", "2.0.0", "2024.1.1.1",
	}
	for i := 0; i < len(ladder); i++ {
		for j := i + 1; j < len(ladder); j++ {
			if got := cmpVersion(ladder[i], ladder[j]); got != -1 {
				t.Fatalf("cmpVersion(%q,%q)=%d want -1 (index %d before %d)",
					ladder[i], ladder[j], got, i, j)
			}
		}
	}
}
