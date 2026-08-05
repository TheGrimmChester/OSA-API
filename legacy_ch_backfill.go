package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

const hubClickHouseDB = "opa"

// osaLegacyBackfillTables are OSA product tables that may still hold rows only in
// hub opa.* while Query() rewrites opa → osa.
var osaLegacyBackfillTables = []string{
	"security_runs",
	"secret_findings",
	"sast_findings",
	"iac_findings",
	"vuln_findings",
	"iast_findings",
	"service_dependencies",
}

func needsLegacyHubFallback() bool {
	db := clickHouseDatabase()
	return db != "" && db != hubClickHouseDB && db != "default"
}

func backfillLegacySecurityTablesOnBoot() int {
	if queryClient == nil || !needsLegacyHubFallback() {
		return 0
	}
	total := 0
	for _, table := range osaLegacyBackfillTables {
		total += backfillLegacySecurityTableOnBoot(table)
	}
	if total > 0 {
		log.Printf("[INFO] OSA legacy hub backfill: %d row(s) copied from opa.* to %s.*",
			total, clickHouseDatabase())
	}
	return total
}

func backfillLegacySecurityTableOnBoot(table string) int {
	if queryClient == nil || table == "" || !needsLegacyHubFallback() {
		return 0
	}
	productDB := clickHouseDatabase()
	hubN, err := chTableRowCount(hubClickHouseDB, table)
	if err != nil || hubN == 0 {
		return 0
	}
	prodN, err := chTableRowCount(productDB, table)
	if err != nil {
		log.Printf("[WARN] legacy backfill %s: product count: %v", table, err)
		return 0
	}
	if prodN >= hubN {
		return 0
	}
	// Column-explicit, not SELECT *.
	//
	// `SELECT *` requires the two tables to have identical column arity in
	// identical order. The moment the product schema gains a column the hub side
	// does not have — which every additive `ADD COLUMN IF NOT EXISTS` migration
	// does — ClickHouse answers NUMBER_OF_COLUMNS_DOESNT_MATCH, and the error is
	// swallowed into a [WARN] below. The backfill then silently stops working for
	// that table, and the symptom is missing legacy rows nobody connects to a
	// schema change made months earlier.
	//
	// main.go runs the schema before this, so a new column is present on the
	// product side by the time the backfill runs: the breakage is certain rather
	// than hypothetical.
	cols, err := chSharedColumns(hubClickHouseDB, productDB, table)
	if err != nil {
		log.Printf("[WARN] legacy backfill %s: column intersect: %v", table, err)
		return 0
	}
	if len(cols) == 0 {
		log.Printf("[WARN] legacy backfill %s: no columns in common between %s and %s",
			table, hubClickHouseDB, productDB)
		return 0
	}
	list := strings.Join(cols, ", ")
	sql := fmt.Sprintf("INSERT INTO %s.%s (%s) SELECT %s FROM %s.%s",
		productDB, table, list, list, hubClickHouseDB, table)
	if err := queryClient.ExecuteExact(sql); err != nil {
		log.Printf("[WARN] legacy backfill %s: %v", table, err)
		return 0
	}
	after, _ := chTableRowCount(productDB, table)
	if after > prodN {
		return int(after - prodN)
	}
	return 0
}

func chTableRowCount(db, table string) (uint64, error) {
	rows, err := queryClient.QueryExact(fmt.Sprintf(
		"SELECT count() AS c FROM %s.%s", db, table))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return countFromRow(rows[0])
}

// countFromRow extracts a count() value from a ClickHouse JSON row.
//
// Split out from chTableRowCount so the type handling is testable: it was wrong for
// the only shape that occurs in production, and no test could reach it.
func countFromRow(row map[string]interface{}) (uint64, error) {
	switch v := row["c"].(type) {
	case float64:
		return uint64(v), nil
	case uint64:
		return v, nil
	case int64:
		if v < 0 {
			return 0, nil
		}
		return uint64(v), nil
	case string:
		// ClickHouse serialises UInt64 as a QUOTED STRING in JSON — {"c":"2"} —
		// to avoid the precision loss of a JavaScript number. count() is UInt64,
		// so this is the ONLY case that ever runs in production.
		//
		// Without it every count fell through to `default: return 0`, which made
		// backfillLegacySecurityTableOnBoot bail at `hubN == 0` for every table on
		// every boot. The legacy backfill has therefore never copied a row — the
		// [WARN] path its callers guard against was never even reached.
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("unparseable count %q: %w", v, err)
		}
		return n, nil
	default:
		// An unrecognised type must be an error, not a silent zero. A zero here is
		// indistinguishable from an empty table and disables the backfill without
		// saying so — which is exactly how the string case went unnoticed.
		return 0, fmt.Errorf("unexpected count type %T", v)
	}
}

// chSharedColumns returns the columns a table has in BOTH databases, in the
// product table's own order.
//
// Product order rather than hub order because the INSERT names its target columns
// explicitly, so the two lists must agree with each other — and using the target's
// order keeps the generated SQL stable and readable when it appears in a log.
//
// A column only the hub has is dropped: it holds data this build has no place to
// put. A column only the product has keeps its DEFAULT, which is exactly what an
// additive migration intends.
func chSharedColumns(hubDB, productDB, table string) ([]string, error) {
	if queryClient == nil {
		return nil, fmt.Errorf("no clickhouse query client")
	}
	hubCols, err := chColumnSet(hubDB, table)
	if err != nil {
		return nil, err
	}
	// position keeps the product's declared order; system.columns exposes it, and
	// sorting by name instead would produce a valid but gratuitously shuffled list.
	rows, err := queryClient.QueryExact(fmt.Sprintf(
		"SELECT name FROM system.columns WHERE database = '%s' AND table = '%s' ORDER BY position",
		escapeSQL(productDB), escapeSQL(table)))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		name := getString(row, "name")
		if name == "" || !hubCols[name] {
			continue
		}
		// Backtick-quote: a column named like a keyword is legal in ClickHouse and
		// would otherwise produce a syntax error in the generated INSERT.
		out = append(out, "`"+name+"`")
	}
	return out, nil
}

func chColumnSet(db, table string) (map[string]bool, error) {
	rows, err := queryClient.QueryExact(fmt.Sprintf(
		"SELECT name FROM system.columns WHERE database = '%s' AND table = '%s'",
		escapeSQL(db), escapeSQL(table)))
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(rows))
	for _, row := range rows {
		if name := getString(row, "name"); name != "" {
			set[name] = true
		}
	}
	return set, nil
}
