package main

import (
	"fmt"
	"log"
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
	sql := fmt.Sprintf("INSERT INTO %s.%s SELECT * FROM %s.%s",
		productDB, table, hubClickHouseDB, table)
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
	switch v := rows[0]["c"].(type) {
	case float64:
		return uint64(v), nil
	case uint64:
		return v, nil
	case int64:
		if v < 0 {
			return 0, nil
		}
		return uint64(v), nil
	default:
		return 0, nil
	}
}
