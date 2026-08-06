package main

import (
	"math"
	"testing"
)

func TestScannerSubscore(t *testing.T) {
	if got := scannerSubscore(nil); got != 100 {
		t.Fatalf("empty = %v want 100", got)
	}
	if got := scannerSubscore(map[string]int{"info": 50}); got != 100 {
		t.Fatalf("info ignored = %v want 100", got)
	}
	if got := scannerSubscore(map[string]int{"critical": 1}); got != 80 {
		t.Fatalf("1 critical = %v want 80", got)
	}
	if got := scannerSubscore(map[string]int{"blocker": 5}); got != 0 {
		t.Fatalf("catastrophic = %v want 0", got)
	}
	if got := scannerSubscore(map[string]int{"high": 2, "medium": 5}); got != 60 {
		t.Fatalf("mixed = %v want 60", got)
	}
}

func TestMergePreservesOtherScanners(t *testing.T) {
	sast := 54.0
	prev := emptyRepoScoreState("org", "proj", "acme/app")
	prev.Scanners["sast"] = ScannerFacet{Score: &sast, RunID: "run-sast", FindingCount: 3}
	prev.Score, prev.ProblemCount = compositeScore(prev.Scanners)

	next := mergeScannerFacets(prev, "org", "proj", "acme/app", "run-secrets", "2026-08-06 12:00:00.000",
		[]string{"secrets"},
		map[string]map[string]int{"secrets": {"high": 1}},
		map[string]int{"secrets": 1},
	)

	if next.Scanners["sast"].Score == nil || *next.Scanners["sast"].Score != 54 {
		t.Fatalf("sast facet lost: %+v", next.Scanners["sast"])
	}
	if next.Scanners["secrets"].Score == nil || *next.Scanners["secrets"].Score != 90 {
		t.Fatalf("secrets facet = %+v want score 90", next.Scanners["secrets"])
	}
	if next.Score == nil {
		t.Fatal("composite score missing")
	}
	want := math.Round((54+90)/2*10) / 10
	if *next.Score != want {
		t.Fatalf("composite = %v want %v", *next.Score, want)
	}
	if next.Scanners["secrets"].RunID != "run-secrets" {
		t.Fatalf("secrets run_id = %q", next.Scanners["secrets"].RunID)
	}
	if next.Scanners["sast"].RunID != "run-sast" {
		t.Fatalf("sast run_id overwritten: %q", next.Scanners["sast"].RunID)
	}
}

func TestCompositeOmitsUnmeasured(t *testing.T) {
	scanners := map[string]ScannerFacet{}
	a, b := 100.0, 50.0
	scanners["secrets"] = ScannerFacet{Score: &a, FindingCount: 0}
	scanners["cve"] = ScannerFacet{Score: &b, FindingCount: 4}
	score, problems := compositeScore(scanners)
	if score == nil || *score != 75 {
		t.Fatalf("mean = %v want 75", score)
	}
	if problems != 4 {
		t.Fatalf("problems = %d want 4", problems)
	}
}

func TestUpdateRepoScoreAfterRunPartial(t *testing.T) {
	repoScoreMu.Lock()
	repoScoreCache = map[string]*RepoScoreState{}
	repoScoreMu.Unlock()

	updateRepoScoreAfterRun("o", "p", "acme/x", "r1",
		`{"counts":{"secrets":0,"sast":2},"severity_counts":{"sast":{"high":2}}}`,
		[]string{"secrets", "sast"}, "2026-08-06 10:00:00.000")
	first := loadRepoScoreCached("o", "p", "acme/x")
	if first == nil || first.Score == nil {
		t.Fatal("first rollup missing")
	}
	sast1 := *first.Scanners["sast"].Score

	updateRepoScoreAfterRun("o", "p", "acme/x", "r2",
		`{"counts":{"secrets":0},"severity_counts":{"secrets":{}}}`,
		[]string{"secrets"}, "2026-08-06 11:00:00.000")
	second := loadRepoScoreCached("o", "p", "acme/x")
	if second.Scanners["sast"].Score == nil || *second.Scanners["sast"].Score != sast1 {
		t.Fatalf("partial secrets scan wiped sast: %+v", second.Scanners["sast"])
	}
	if second.Scanners["secrets"].RunID != "r2" {
		t.Fatalf("secrets not updated to r2")
	}
}
