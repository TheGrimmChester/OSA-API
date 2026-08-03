package main

import "testing"

func TestCmpSemver(t *testing.T) {
	if cmpSemver("4.17.20", "4.17.21") >= 0 {
		t.Fatal("expected lower")
	}
	if cmpSemver("1.6.0", "1.6.0") != 0 {
		t.Fatal()
	}
	if cmpSemver("2.0.0", "1.9.9") <= 0 {
		t.Fatal()
	}
}

func TestVersionLikelyVulnerable(t *testing.T) {
	if !versionLikelyVulnerable("4.17.20", "<4.17.21") {
		t.Fatal()
	}
	if versionLikelyVulnerable("4.17.21", "<4.17.21") {
		t.Fatal()
	}
	if !versionLikelyVulnerable("", "<1.0.0") {
		t.Fatal("unknown version should keep finding")
	}
}
