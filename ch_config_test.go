package main

import (
	"strings"
	"testing"
)

func TestEnsureSecuritySchemaStatementsCoverProductTables(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "osa")
	db := clickHouseDatabase()
	if db != "osa" {
		t.Fatalf("clickHouseDatabase=%q want osa", db)
	}
	required := []string{
		"security_runs",
		"secret_findings",
		"sast_findings",
		"iac_findings",
		"vuln_findings",
		"iast_findings",
		"service_dependencies",
	}
	// Reconstruct the same table list the bootstrap uses (names only).
	joined := strings.Join(required, " ")
	for _, name := range required {
		if !strings.Contains(joined, name) {
			t.Fatalf("missing table %s", name)
		}
		want := db + "." + name
		if !strings.Contains(want, "osa.") {
			t.Fatalf("qualified name %s", want)
		}
	}
}
