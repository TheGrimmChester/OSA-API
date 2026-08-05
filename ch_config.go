package main

import (
	"log"
	"os"
	"strings"
)

// clickHouseDatabase resolves the product ClickHouse database name.
// Precedence: CLICKHOUSE_DB > CLICKHOUSE_DATABASE > product default.
func clickHouseDatabase() string {
	if v := strings.TrimSpace(os.Getenv("CLICKHOUSE_DB")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("CLICKHOUSE_DATABASE")); v != "" {
		return v
	}
	return defaultClickHouseDB
}

// ensureClickHouseDatabase creates the product DB when a query client is available.
func ensureClickHouseDatabase(q *ClickHouseQuery) {
	if q == nil {
		return
	}
	db := q.database
	if db == "" || db == "default" {
		return
	}
	_ = q.Execute("CREATE DATABASE IF NOT EXISTS " + db)
}

// ensureSecuritySchema creates OSA product tables in CLICKHOUSE_DB.
// Without this, legacy SQL rewrite (opa.* → osa.*) targets an empty database and
// dashboard list endpoints return ClickHouse UNKNOWN_TABLE errors.
func ensureSecuritySchema(q *ClickHouseQuery) {
	if q == nil {
		return
	}
	db := clickHouseDatabase()
	if db == "" || db == "default" {
		return
	}
	for _, s := range securitySchemaStatements(db) {
		if err := q.Execute(s); err != nil {
			log.Printf("security schema: %v", err)
		}
	}
	ensureSecurityColumns(q, db)
}

// securitySchemaStatements returns the CREATE TABLE statements for the product
// database.
//
// A pure function so tests can assert what is actually created. The previous test
// could not reach this list — it was a local slice — so it compared a hardcoded
// table list against itself and would have passed with the schema entirely empty.
func securitySchemaStatements(db string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + db + `.security_runs (
			id String,
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service LowCardinality(String) DEFAULT '',
			profile LowCardinality(String) DEFAULT 'auto',
			scanners_json String DEFAULT '[]',
			target_path String DEFAULT '',
			image String DEFAULT '',
			status LowCardinality(String) DEFAULT 'running',
			summary_json String DEFAULT '{}',
			error String DEFAULT '',
			started_at DateTime64(3) DEFAULT now64(3),
			finished_at DateTime64(3) DEFAULT now64(3),
			repo_full_name String DEFAULT '',
			pr_number Int32 DEFAULT 0,
			commit_sha String DEFAULT '',
			scm_job_id String DEFAULT ''
		) ENGINE = ReplacingMergeTree(finished_at)
		ORDER BY (organization_id, project_id, id)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.secret_findings (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service LowCardinality(String) DEFAULT '',
			rule String DEFAULT '',
			severity LowCardinality(String) DEFAULT 'high',
			file String DEFAULT '',
			line UInt32 DEFAULT 0,
			snippet String DEFAULT '',
			detector LowCardinality(String) DEFAULT 'manual',
			scraped_at DateTime64(3) DEFAULT now64(3),
			security_run_id String DEFAULT ''
		) ENGINE = MergeTree
		PARTITION BY toDate(scraped_at)
		ORDER BY (organization_id, project_id, service, scraped_at)
		TTL toDateTime(scraped_at) + toIntervalDay(90)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.sast_findings (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service LowCardinality(String) DEFAULT '',
			rule String DEFAULT '',
			file String DEFAULT '',
			line UInt32 DEFAULT 0,
			severity LowCardinality(String) DEFAULT 'medium',
			message String DEFAULT '',
			scraped_at DateTime64(3) DEFAULT now64(3),
			security_run_id String DEFAULT ''
		) ENGINE = MergeTree
		PARTITION BY toDate(scraped_at)
		ORDER BY (organization_id, project_id, scraped_at)
		TTL toDateTime(scraped_at) + toIntervalDay(90)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.iac_findings (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service LowCardinality(String) DEFAULT '',
			kind LowCardinality(String) DEFAULT 'iac',
			rule String DEFAULT '',
			file String DEFAULT '',
			severity LowCardinality(String) DEFAULT 'medium',
			message String DEFAULT '',
			scraped_at DateTime64(3) DEFAULT now64(3),
			security_run_id String DEFAULT ''
		) ENGINE = MergeTree
		PARTITION BY toDate(scraped_at)
		ORDER BY (organization_id, project_id, kind, scraped_at)
		TTL toDateTime(scraped_at) + toIntervalDay(90)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.vuln_findings (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service String,
			release String DEFAULT '',
			ecosystem LowCardinality(String) DEFAULT '',
			package_name String,
			version String DEFAULT '',
			advisory_id String,
			severity LowCardinality(String) DEFAULT 'medium',
			summary String DEFAULT '',
			reachability LowCardinality(String) DEFAULT 'not_observed',
			path_hash String DEFAULT '',
			path_hits UInt64 DEFAULT 0,
			scraped_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(scraped_at)
		ORDER BY (organization_id, project_id, service, advisory_id, package_name, version)
		TTL toDateTime(scraped_at) + toIntervalDay(90)`,

		// cve_findings is the per-run, immutable CVE surface: what the gate reads,
		// what a PR check cites, what an audit reconstructs.
		//
		// It is a NEW table rather than columns on vuln_findings because
		// vuln_findings cannot be extended into this shape: ClickHouse cannot ALTER
		// an ORDER BY key, and that key (org, proj, service, advisory_id,
		// package_name, version) has no run dimension at all. Two scans of two
		// branches would collapse onto one row.
		//
		// vuln_findings stays the tenant "current state" rollup behind /api/vulns/*;
		// the CVE scanner dual-writes, and that dual write IS the migration path.
		`CREATE TABLE IF NOT EXISTS ` + db + `.cve_findings (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			security_run_id String DEFAULT '',
			service LowCardinality(String) DEFAULT '',
			ref String DEFAULT '',
			pr_number Int32 DEFAULT 0,
			commit_sha String DEFAULT '',
			ecosystem LowCardinality(String) DEFAULT '',
			package_name String DEFAULT '',
			version String DEFAULT '',
			dep_scope LowCardinality(String) DEFAULT 'unknown',
			dep_depth UInt8 DEFAULT 0,
			manifest String DEFAULT '',
			advisory_id String DEFAULT '',
			cve_id String DEFAULT '',
			aliases_json String DEFAULT '[]',
			severity LowCardinality(String) DEFAULT 'unknown',
			cvss_score Float32 DEFAULT 0,
			cvss_vector String DEFAULT '',
			cvss_version LowCardinality(String) DEFAULT '',
			cvss_source LowCardinality(String) DEFAULT '',
			cwe_json String DEFAULT '[]',
			kev UInt8 DEFAULT 0,
			kev_known UInt8 DEFAULT 0,
			kev_date_added String DEFAULT '',
			epss Float32 DEFAULT 0,
			epss_percentile Float32 DEFAULT 0,
			epss_known UInt8 DEFAULT 0,
			fixed_version String DEFAULT '',
			fix_state LowCardinality(String) DEFAULT 'unknown',
			introduced_version String DEFAULT '',
			reachability LowCardinality(String) DEFAULT 'not_observed',
			path_hash String DEFAULT '',
			path_hits UInt64 DEFAULT 0,
			summary String DEFAULT '',
			references_json String DEFAULT '[]',
			sources_json String DEFAULT '[]',
			published_at String DEFAULT '',
			modified_at String DEFAULT '',
			scraped_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(scraped_at)
		PARTITION BY toDate(scraped_at)
		ORDER BY (organization_id, project_id, security_run_id, package_name, version, cve_id, advisory_id)
		TTL toDateTime(scraped_at) + toIntervalDay(90)`,

		`CREATE TABLE IF NOT EXISTS ` + db + `.iast_findings (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service String DEFAULT '',
			sink LowCardinality(String),
			evidence String DEFAULT '',
			route String DEFAULT '',
			trace_id String DEFAULT '',
			span_id String DEFAULT '',
			scraped_at DateTime64(3) DEFAULT now64(3),
			blocked UInt8 DEFAULT 0,
			detector LowCardinality(String) DEFAULT ''
		) ENGINE = MergeTree
		PARTITION BY toDate(scraped_at)
		ORDER BY (organization_id, project_id, sink, scraped_at)
		TTL toDateTime(scraped_at) + toIntervalDay(30)`,
		`CREATE TABLE IF NOT EXISTS ` + db + `.service_dependencies (
			organization_id String DEFAULT '',
			project_id String DEFAULT '',
			service String,
			release String DEFAULT '',
			ecosystem LowCardinality(String) DEFAULT '',
			package_name String,
			version String DEFAULT '',
			purl String DEFAULT '',
			scraped_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(scraped_at)
		ORDER BY (organization_id, project_id, service, release, ecosystem, package_name, version)
		TTL toDateTime(scraped_at) + toIntervalDay(90)`,
	}
}

// securityColumnMigrations carries an existing install forward.
//
// There is no migration system in OSA-API, so this follows the family idiom
// (ORA-API/agents_prefs.go, OPL-API/ch_config.go): every statement is
// ADD COLUMN IF NOT EXISTS, and a failure is a non-fatal [WARN] rather than a
// refusal to boot. Additive only — nothing here can lose data, so replaying it on
// every start is safe and needs no version table.
//
// Returned as a slice rather than executed inline so a test can assert the shape
// of every statement. A migration list that silently gained a DROP or a MODIFY
// would be a data-loss bug that no other test in this repo would notice.
func securityColumnMigrations(db string) []string {
	return []string{
		// The branch or tag that was scanned. Accepted by the API and passed to
		// git clone today, but never persisted — which is why RunDetail always
		// reads "default branch" no matter what was actually scanned.
		"ALTER TABLE " + db + ".security_runs ADD COLUMN IF NOT EXISTS ref String DEFAULT ''",
		// branch | pull_request | workspace. An explicit discriminator rather than
		// inferring from which field happens to be populated.
		"ALTER TABLE " + db + ".security_runs ADD COLUMN IF NOT EXISTS target_kind LowCardinality(String) DEFAULT ''",
		// The CVE scanner dual-writes into vuln_findings so /api/vulns/* starts
		// showing real CVEs with no dashboard change. These are the columns that
		// carries.
		"ALTER TABLE " + db + ".vuln_findings ADD COLUMN IF NOT EXISTS cve_id String DEFAULT ''",
		"ALTER TABLE " + db + ".vuln_findings ADD COLUMN IF NOT EXISTS cvss_score Float32 DEFAULT 0",
		"ALTER TABLE " + db + ".vuln_findings ADD COLUMN IF NOT EXISTS fixed_version String DEFAULT ''",
		"ALTER TABLE " + db + ".vuln_findings ADD COLUMN IF NOT EXISTS kev UInt8 DEFAULT 0",
		"ALTER TABLE " + db + ".vuln_findings ADD COLUMN IF NOT EXISTS security_run_id String DEFAULT ''",
	}
}

func ensureSecurityColumns(q *ClickHouseQuery, db string) {
	if q == nil || db == "" || db == "default" {
		return
	}
	for _, s := range securityColumnMigrations(db) {
		if err := q.Execute(s); err != nil {
			// Non-fatal by design. A column that already exists, or a table an
			// older deployment has not created yet, must not stop the service from
			// serving everything else.
			log.Printf("[WARN] security column migration: %v", err)
		}
	}
}
