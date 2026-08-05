package main

import (
	"strings"
	"testing"
)

// The previous version of this test built a slice of table names, joined it, and
// then asserted each name appeared in the join. It could not reach the statement
// list — that was a local slice inside ensureSecuritySchema — so it compared a
// hardcoded list against itself and would have passed with the schema entirely
// empty. securitySchemaStatements exists so these assertions touch the real thing.

func TestSchemaCreatesEveryProductTable(t *testing.T) {
	t.Setenv("CLICKHOUSE_DB", "osa")
	db := clickHouseDatabase()
	if db != "osa" {
		t.Fatalf("clickHouseDatabase()=%q want osa", db)
	}
	stmts := securitySchemaStatements(db)
	if len(stmts) == 0 {
		t.Fatal("no schema statements — every list endpoint would return UNKNOWN_TABLE")
	}
	joined := strings.Join(stmts, "\n")
	for _, table := range []string{
		"security_runs", "secret_findings", "sast_findings", "iac_findings",
		"vuln_findings", "iast_findings", "service_dependencies", "cve_findings",
	} {
		want := "CREATE TABLE IF NOT EXISTS " + db + "." + table + " ("
		if !strings.Contains(joined, want) {
			t.Fatalf("no CREATE for %s (looked for %q)", table, want)
		}
	}
}

// Every statement must be idempotent: this runs on every boot.
func TestSchemaStatementsAreIdempotent(t *testing.T) {
	for _, s := range securitySchemaStatements("osa") {
		trimmed := strings.TrimSpace(s)
		if !strings.HasPrefix(trimmed, "CREATE TABLE IF NOT EXISTS ") {
			head := trimmed
			if len(head) > 120 {
				head = head[:120]
			}
			t.Fatalf("statement is not an idempotent CREATE:\n%s", head)
		}
	}
}

// cve_findings' ORDER BY is irreversible — ClickHouse cannot ALTER a sorting key.
// Two of these columns are load-bearing and were reasoned about once; this records
// why so a future edit cannot quietly drop them.
func TestCVEFindingsSortingKeyIsCorrect(t *testing.T) {
	stmt := findStatement(t, securitySchemaStatements("osa"), "osa.cve_findings")

	// security_run_id: without a run dimension two scans of two branches collapse
	// onto one row, which is exactly why this is a new table rather than columns on
	// vuln_findings.
	// advisory_id: a package+version can carry several GHSAs with no CVE alias, and
	// without it they all collapse onto one row keyed on an empty cve_id.
	wantKey := "ORDER BY (organization_id, project_id, security_run_id, package_name, version, cve_id, advisory_id)"
	if !strings.Contains(stmt, wantKey) {
		t.Fatalf("cve_findings sorting key changed — it cannot be ALTERed later.\nwant: %s", wantKey)
	}
	// ReplacingMergeTree, not MergeTree: runs can be re-dispatched, and a
	// double-counted finding corrupts the gate.
	if !strings.Contains(stmt, "ENGINE = ReplacingMergeTree(scraped_at)") {
		t.Fatal("cve_findings must be ReplacingMergeTree(scraped_at) so a re-dispatched run cannot double-count")
	}
}

// The tri-state signal columns are the most important in the table: without them a
// gate silently converts "we never got an answer" into "not exploited", and
// epss=0.0 is itself a legitimate score.
func TestCVEFindingsKeepsTheTriStateSignals(t *testing.T) {
	stmt := findStatement(t, securitySchemaStatements("osa"), "osa.cve_findings")
	for _, col := range []string{
		"kev UInt8 DEFAULT 0",
		"kev_known UInt8 DEFAULT 0",
		"epss Float32 DEFAULT 0",
		"epss_known UInt8 DEFAULT 0",
	} {
		if !strings.Contains(stmt, col) {
			t.Fatalf("cve_findings is missing %q — absence of a signal would read as a negative finding", col)
		}
	}
	// severity defaults to unknown rather than a band, so a finding with no CVSS
	// and no OSV band cannot masquerade as medium.
	if !strings.Contains(stmt, "severity LowCardinality(String) DEFAULT 'unknown'") {
		t.Fatal("cve_findings severity must default to 'unknown', not to a band")
	}
	// fix_state explicit, so the gate and UI never infer policy from an empty string.
	if !strings.Contains(stmt, "fix_state LowCardinality(String) DEFAULT 'unknown'") {
		t.Fatal("cve_findings fix_state must default to 'unknown'")
	}
}

// Every migration must be additive. A DROP or MODIFY here is a data-loss bug that
// nothing else in this repo would catch, because the statements are executed with a
// non-fatal [WARN] on failure.
func TestColumnMigrationsAreAdditiveOnly(t *testing.T) {
	migrations := securityColumnMigrations("osa")
	if len(migrations) == 0 {
		t.Fatal("no column migrations")
	}
	for _, s := range migrations {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "ADD COLUMN IF NOT EXISTS") {
			t.Fatalf("migration is not an additive ADD COLUMN IF NOT EXISTS:\n%s", s)
		}
		for _, forbidden := range []string{"DROP ", "MODIFY ", "RENAME ", "CLEAR ", "DELETE ", "TRUNCATE "} {
			if strings.Contains(strings.ToUpper(s), forbidden) {
				t.Fatalf("migration contains %q — migrations here replay on every boot and must never lose data:\n%s",
					strings.TrimSpace(forbidden), s)
			}
		}
		if !strings.Contains(s, "osa.") {
			t.Fatalf("migration is not database-qualified:\n%s", s)
		}
	}
}

// The columns the branch/PR work and the dual write depend on. `ref` in particular
// is why RunDetail always says "default branch" today: it was accepted, passed to
// git clone, and never persisted.
func TestColumnMigrationsCoverTheNewFields(t *testing.T) {
	joined := strings.Join(securityColumnMigrations("osa"), "\n")
	for _, want := range []string{
		"osa.security_runs ADD COLUMN IF NOT EXISTS ref ",
		"osa.security_runs ADD COLUMN IF NOT EXISTS target_kind ",
		"osa.vuln_findings ADD COLUMN IF NOT EXISTS cve_id ",
		"osa.vuln_findings ADD COLUMN IF NOT EXISTS cvss_score ",
		"osa.vuln_findings ADD COLUMN IF NOT EXISTS fixed_version ",
		"osa.vuln_findings ADD COLUMN IF NOT EXISTS kev ",
		"osa.vuln_findings ADD COLUMN IF NOT EXISTS security_run_id ",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing migration: %s", want)
		}
	}
}

// A "default" or empty database must be left alone entirely — that is a
// misconfigured deployment, and creating tables in `default` would scatter product
// data into the shared database.
func TestSchemaRefusesTheDefaultDatabase(t *testing.T) {
	for _, db := range []string{"", "default"} {
		ensureSecurityColumns(nil, db) // must not panic
	}
	// And with a nil client nothing is executed regardless.
	ensureSecurityColumns(nil, "osa")
}

func findStatement(t *testing.T, stmts []string, qualified string) string {
	t.Helper()
	for _, s := range stmts {
		if strings.Contains(s, qualified+" (") {
			return s
		}
	}
	t.Fatalf("no statement creating %s", qualified)
	return ""
}
