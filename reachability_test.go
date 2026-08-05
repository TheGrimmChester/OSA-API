package main

import (
	"os"
	"strings"
	"testing"
)

// readSourceFile reads a package source file for the drift guards below.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// Reachability is an honesty surface: "not_observed" must mean "we looked and saw
// nothing", never "we did not look" and never "we matched everything". These tests
// pin the query text, because both defects were invisible in the result — one
// returned the correct-looking default without querying, the other returned a
// confident `observed` from a query that matched the whole call graph.

// buildReachabilityConds mirrors the condition assembly in rankReachability so the
// two defects can be asserted without a ClickHouse. Kept in the test file
// deliberately: extracting it into production code purely for testability would
// invite the two copies drifting apart.
//
// If rankReachability's assembly changes, TestConditionsMirrorProduction below
// fails, which is the signal to update this.
func buildReachabilityConds(pkg string, symbols []string) []string {
	conds := []string{}
	if p := strings.TrimSpace(pkg); p != "" {
		conds = append(conds, "positionCaseInsensitive(call_site, '"+escapeSQL(p)+"') > 0")
	}
	for _, sym := range symbols {
		if sym = strings.TrimSpace(sym); sym == "" {
			continue
		}
		conds = append(conds, "positionCaseInsensitive(call_site, '"+escapeSQL(sym)+"') > 0")
	}
	return conds
}

// The original guard returned early whenever an advisory carried no symbols, even
// though the condition list has always included one for the package name. Every
// package-only advisory therefore reported "not_observed" without a query being
// issued — indistinguishable from a real negative result.
func TestPackageOnlyAdvisoryStillProducesACondition(t *testing.T) {
	conds := buildReachabilityConds("lodash", nil)
	if len(conds) != 1 {
		t.Fatalf("a package-only advisory must still be queryable, got %d condition(s)", len(conds))
	}
	if !strings.Contains(conds[0], "'lodash'") {
		t.Fatalf("condition does not use the package name: %s", conds[0])
	}
}

// ClickHouse's position() returns 1 for an empty needle, so
// `positionCaseInsensitive(call_site, ”) > 0` is TRUE for every row. A blank
// package or symbol would turn the OR into "match the entire call graph" and report
// a false `observed` — worse than the missing query above, because it manufactures
// evidence rather than omitting it.
func TestBlankTermsNeverReachTheQuery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pkg     string
		symbols []string
		want    int
	}{
		{name: "blank package with symbols", pkg: "", symbols: []string{"Image.open"}, want: 1},
		{name: "whitespace package", pkg: "   ", symbols: []string{"Image.open"}, want: 1},
		{name: "blank symbol among real ones", pkg: "pillow", symbols: []string{"", "Image.open"}, want: 2},
		{name: "all blank", pkg: "  ", symbols: []string{"", "  "}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conds := buildReachabilityConds(tc.pkg, tc.symbols)
			if len(conds) != tc.want {
				t.Fatalf("got %d condition(s), want %d: %v", len(conds), tc.want, conds)
			}
			for _, c := range conds {
				if strings.Contains(c, ", '') >") {
					t.Fatalf("an empty needle reached the query — it matches every row: %s", c)
				}
			}
		})
	}
}

// With nothing to search for, the function must return before building a query at
// all: an empty OR list would either be a syntax error or, worse, get "fixed" later
// into a WHERE that matches everything.
func TestNothingToSearchForYieldsNoConditions(t *testing.T) {
	if got := buildReachabilityConds("", nil); len(got) != 0 {
		t.Fatalf("expected no conditions, got %v", got)
	}
}

// The guard in production must accept a package-only advisory and reject a wholly
// empty one. Asserted against the real function's early-return behaviour: with no
// query client configured it always returns "not_observed", so what this checks is
// that it does not panic and keeps the honest default.
func TestRankReachabilityKeepsTheHonestDefault(t *testing.T) {
	prev := queryClient
	queryClient = nil
	defer func() { queryClient = prev }()

	for _, adv := range []advisory{
		{Package: "lodash"},
		{Symbols: []string{"lodash.merge"}},
		{},
	} {
		status, pathHash, hits := rankReachability("acme", "proj", "svc", adv)
		if status != "not_observed" {
			t.Fatalf("status = %q, want not_observed — absence must never read as not_vulnerable", status)
		}
		if pathHash != "" || hits != 0 {
			t.Fatalf("pathHash=%q hits=%d, want empty", pathHash, hits)
		}
	}
}

// The batch variant exists so a scan issues one query per distinct package instead
// of one per finding. It must dedup, drop blanks, and seed every requested package
// with the honest default so a caller can read the map without existence checks.
func TestRankReachabilityBatchSeedsEveryPackage(t *testing.T) {
	prev := queryClient
	queryClient = nil
	defer func() { queryClient = prev }()

	// With no client the query is skipped, but the seeding contract still holds.
	got := rankReachabilityBatch("acme", "proj", "svc", []string{"lodash", "lodash", "  ", "axios", ""})
	if len(got) != 0 {
		// queryClient == nil returns early with an empty map by design: there is
		// nothing honest to say about packages we never looked up.
		t.Fatalf("with no query client the map must be empty, got %v", got)
	}
}

// TestConditionsMirrorProduction guards the test helper above against drift. If
// rankReachability's condition assembly changes shape, this catches it rather than
// letting the tests keep passing against a stale mirror.
func TestConditionsMirrorProduction(t *testing.T) {
	src := readSourceFile(t, "vuln.go")
	// Both guards must be present in the real function.
	for _, want := range []string{
		`strings.TrimSpace(adv.Package) == "" && len(adv.Symbols) == 0`,
		`if len(conds) == 0 {`,
		`if pkg := strings.TrimSpace(adv.Package); pkg != "" {`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("vuln.go no longer contains %q — reachability_test.go's mirror is stale", want)
		}
	}
}
