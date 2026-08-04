package main

import (
	"fmt"
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

func TestLegacyBackfillInsertSQL(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "osa")
	sql := fmt.Sprintf("INSERT INTO %s.%s SELECT * FROM %s.%s",
		clickHouseDatabase(), "security_runs", hubClickHouseDB, "security_runs")
	if !strings.Contains(sql, "INSERT INTO osa.security_runs SELECT * FROM opa.security_runs") {
		t.Fatalf("unexpected sql: %q", sql)
	}
}
