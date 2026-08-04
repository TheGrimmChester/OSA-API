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
	stmts := []string{
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
	for _, s := range stmts {
		if err := q.Execute(s); err != nil {
			log.Printf("security schema: %v", err)
		}
	}
}
