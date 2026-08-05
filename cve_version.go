package main

import (
	"strconv"
	"strings"
)

// Version handling for CVE findings.
//
// THE central decision: version comparison plays NO part in deciding whether a
// finding exists. We POST to OSV's /v1/query with an explicit version, so OSV
// applies ecosystem-correct semantics itself — npm semver prerelease rules, PEP
// 440, Composer, Go's +incompatible and pseudo-versions. Reimplementing four
// ecosystems' ordering would be this product's single largest source of false
// positives, and a false "you are vulnerable" is worse than a missed advisory
// because it burns the reader's trust in every other finding.
//
// A comparator is still needed for two narrow jobs, neither of which affects
// whether a finding exists:
//
//   1. picking the NEAREST fix among several `fixed` events
//   2. ordering versions for display
//
// Masterminds/semver would be the first direct third-party dependency in this repo
// and still would not handle PEP 440 or Composer, so it does not solve the general
// problem either.

// cmpVersion orders two version strings.
//
// ORDERING ONLY. Never use this to decide vulnerability membership — OSV decides
// that, with the ecosystem's real rules.
//
// Returns -1, 0 or 1.
func cmpVersion(a, b string) int {
	an, apre := splitVersion(a)
	bn, bpre := splitVersion(b)

	// Unbounded numeric segments, not a fixed [3]int: `1.2.3.4` is real, and PyPI
	// ships things like `2024.1.1.1`. A fixed-width comparison silently truncates
	// them into equality.
	for i := 0; i < len(an) || i < len(bn); i++ {
		av, bv := 0, 0
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}

	// semver §11: a version WITH a prerelease is lower than the same version
	// without one. Getting this backwards would make `1.0.0-rc1` look newer than
	// `1.0.0` and pick a prerelease as the "nearest fix".
	switch {
	case apre == "" && bpre == "":
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return cmpPrerelease(apre, bpre)
}

// splitVersion returns the numeric segments and the prerelease tail.
//
// Tolerant by design: a leading `v` or `=`, and build metadata after `+`, are
// stripped rather than treated as errors, because they appear routinely in real
// lockfiles and manifests.
func splitVersion(v string) ([]int, string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "v")
	// Build metadata is explicitly NOT part of precedence (semver §10).
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	var nums []int
	for _, seg := range strings.Split(v, ".") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		// A segment like `1rc2` (no separator) contributes its numeric head and
		// pushes the rest into the prerelease, which is how PEP 440's `1.0rc1`
		// orders correctly against `1.0`.
		digits := 0
		for digits < len(seg) && seg[digits] >= '0' && seg[digits] <= '9' {
			digits++
		}
		if digits == 0 {
			if pre == "" {
				pre = seg
			}
			break
		}
		n, err := strconv.Atoi(seg[:digits])
		if err != nil {
			break
		}
		nums = append(nums, n)
		if digits < len(seg) {
			if pre == "" {
				pre = seg[digits:]
			}
			break
		}
	}
	return nums, pre
}

// cmpPrerelease applies semver §11 to the dot-separated prerelease identifiers:
// numeric identifiers compare numerically and rank below alphanumeric ones, and a
// larger set of fields wins when all preceding fields are equal.
func cmpPrerelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aNum := strconv.Atoi(as[i])
		bn, bNum := strconv.Atoi(bs[i])
		switch {
		case aNum == nil && bNum == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aNum == nil:
			return -1 // numeric ranks below alphanumeric
		case bNum == nil:
			return 1
		default:
			if as[i] != bs[i] {
				if as[i] < bs[i] {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(as) == len(bs):
		return 0
	case len(as) < len(bs):
		return -1
	default:
		return 1
	}
}

// Fix states. Recorded explicitly so the gate and the UI never have to infer
// policy from an empty string.
const (
	fixStateFixed   = "fixed"   // a concrete version to upgrade to
	fixStateNone    = "none"    // affected, and genuinely no patch yet
	fixStateGit     = "git"     // only a commit fixes it — not an actionable version
	fixStateUnknown = "unknown" // the advisory said nothing usable
)

// osvRange mirrors the subset of OSV's affected[].ranges we read.
type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// nearestFix picks the smallest `fixed` version greater than the installed one —
// the nearest upgrade, not the newest release.
//
// GIT ranges are skipped for the reported version: "upgrade to 4f3a9c…" is
// user-hostile and not something a package manager can act on. But if GIT is the
// ONLY range carrying a fix, the state says so rather than claiming no patch
// exists.
func nearestFix(ranges []osvRange, installed string) (fixed, state string) {
	best := ""
	sawGitFix := false
	sawLastAffected := false
	sawAnyRange := false

	for _, r := range ranges {
		sawAnyRange = true
		isGit := strings.EqualFold(strings.TrimSpace(r.Type), "GIT")
		for _, e := range r.Events {
			if v := strings.TrimSpace(e.LastAffected); v != "" {
				sawLastAffected = true
			}
			v := strings.TrimSpace(e.Fixed)
			if v == "" {
				continue
			}
			if isGit {
				sawGitFix = true
				continue
			}
			// Only a fix ABOVE the installed version is an upgrade. A fix at or
			// below it means this range does not describe our version.
			if installed != "" && cmpVersion(v, installed) <= 0 {
				continue
			}
			if best == "" || cmpVersion(v, best) < 0 {
				best = v
			}
		}
	}

	switch {
	case best != "":
		return best, fixStateFixed
	case sawGitFix:
		return "", fixStateGit
	case sawLastAffected:
		// `last_affected` with no `fixed` is the advisory saying plainly that
		// nothing has been released yet.
		return "", fixStateNone
	case sawAnyRange:
		return "", fixStateNone
	default:
		return "", fixStateUnknown
	}
}

// introducedVersion reports the lowest `introduced` across non-GIT ranges, for
// display. OSV uses "0" to mean "from the beginning".
func introducedVersion(ranges []osvRange) string {
	best := ""
	for _, r := range ranges {
		if strings.EqualFold(strings.TrimSpace(r.Type), "GIT") {
			continue
		}
		for _, e := range r.Events {
			v := strings.TrimSpace(e.Introduced)
			if v == "" || v == "0" {
				continue
			}
			if best == "" || cmpVersion(v, best) < 0 {
				best = v
			}
		}
	}
	return best
}
