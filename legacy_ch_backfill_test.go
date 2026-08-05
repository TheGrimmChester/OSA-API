package main

import (
	"strings"
	"testing"
)

func TestNeedsLegacyHubFallback(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"osa", true},
		{"ora", true},
		{"opa", false},
		{"default", false},
		{"", true},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("CLICKHOUSE_DB", tc.env)
			t.Setenv("CLICKHOUSE_DATABASE", "")
			if got := needsLegacyHubFallback(); got != tc.want {
				t.Fatalf("needsLegacyHubFallback()=%v want %v (CLICKHOUSE_DB=%q)", got, tc.want, tc.env)
			}
		})
	}
}

func TestOsaLegacyBackfillTablesCoverSchema(t *testing.T) {
	required := []string{
		"security_runs",
		"secret_findings",
		"sast_findings",
		"iac_findings",
		"vuln_findings",
		"iast_findings",
		"service_dependencies",
	}
	if len(osaLegacyBackfillTables) != len(required) {
		t.Fatalf("osaLegacyBackfillTables len=%d want %d", len(osaLegacyBackfillTables), len(required))
	}
	seen := map[string]struct{}{}
	for _, name := range osaLegacyBackfillTables {
		seen[name] = struct{}{}
	}
	for _, name := range required {
		if _, ok := seen[name]; !ok {
			t.Fatalf("missing legacy backfill table %s", name)
		}
	}
}

func TestBackfillLegacySecurityTableOnBootSkipsWhenNotProductDB(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "opa")
	if got := backfillLegacySecurityTableOnBoot("security_runs"); got != 0 {
		t.Fatalf("hub-only db should skip backfill, got %d", got)
	}
}

// The previous version of this test built the SQL itself and asserted it contained
// what it had just built — it never touched production code, and it asserted the
// `SELECT *` form that has now been replaced. These read the real source.
//
// `SELECT *` requires identical column arity on both sides, so it breaks the moment
// the product schema gains a column the hub lacks. Every additive migration does
// that, and main.go runs the schema before the backfill, so the breakage is certain
// rather than hypothetical — and the error is swallowed into a [WARN].
func TestBackfillSQLNamesColumnsOnBothSides(t *testing.T) {
	src := readSourceFile(t, "legacy_ch_backfill.go")
	if strings.Contains(src, "SELECT * FROM") {
		t.Fatal("backfill still uses SELECT * — it breaks on any column-arity difference")
	}
	if !strings.Contains(src, "INSERT INTO %s.%s (%s) SELECT %s FROM %s.%s") {
		t.Fatal("backfill INSERT no longer names columns on both sides")
	}
	// Backtick-quoted, because a column named like a keyword is legal in ClickHouse
	// and would otherwise be a syntax error in the generated INSERT.
	if !strings.Contains(src, "\"`\"+name+\"`\"") {
		t.Fatal("shared column names are no longer backtick-quoted")
	}
}

// chTableRowCount returned 0 for EVERY table on every boot, because ClickHouse
// serialises UInt64 as a quoted string in JSON — count() arrives as {"c":"2"} — and
// the type switch had no string case, so every count fell through to a silent zero.
//
// backfillLegacySecurityTableOnBoot bails at `hubN == 0`, so the legacy hub→product
// backfill has never copied a single row on any deployment. Found by running it
// against a live ClickHouse 24.3 and watching 2 hub rows fail to move.
func TestCountParsesClickHousesQuotedUInt64(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     interface{}
		want    uint64
		wantErr bool
	}{
		// The only shape that actually occurs in production.
		{name: "quoted uint64 as ClickHouse sends it", raw: "2", want: 2},
		{name: "quoted zero", raw: "0", want: 0},
		{name: "quoted max uint64", raw: "18446744073709551615", want: 18446744073709551615},
		{name: "whitespace tolerated", raw: " 42 ", want: 42},
		// Shapes another driver or a future ClickHouse could produce.
		{name: "float64", raw: float64(7), want: 7},
		{name: "uint64", raw: uint64(9), want: 9},
		{name: "int64", raw: int64(5), want: 5},
		{name: "negative int64 clamps to zero", raw: int64(-1), want: 0},
		// An unrecognised shape must ERROR, not return a silent zero. A zero is
		// indistinguishable from an empty table and disables the backfill without
		// saying so — exactly how the string case went unnoticed.
		{name: "unparseable string errors", raw: "not-a-number", wantErr: true},
		{name: "unknown type errors", raw: []string{"1"}, wantErr: true},
		{name: "missing key errors", raw: nil, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := countFromRow(map[string]interface{}{"c": tc.raw})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error for %#v, got %d — a silent zero disables the backfill", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %#v: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
