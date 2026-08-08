# Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` / `HTTP_ADDR` | `:8093` | HTTP listen address |
| `JWT_SECRET` | `` | User JWT secret (issue in standalone; validate in co-deployed) |
| `AUTH_MODE` | auto | `standalone` or `codeployed` (auto from `PEER_OPA_URL` when empty) |
| `AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` | `admin` / `admin` | Lab admin seed for standalone login |
| `OPEN_SERVICE_JWT_SECRET` | `` | Service JWT mint/validate secret (required for ORA clone credentials) |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP endpoint |
| `CLICKHOUSE_DB` | `osa` | Product database. Alias: `CLICKHOUSE_DATABASE`. Startup creates this DB and OSA security tables (`security_runs`, `*_findings`, `service_dependencies`) if missing. |
| `PEER_OPA_URL` | `` | OPA hub URL — org/tenancy discovery |
| `PEER_ORA_URL` | `` | ORA API URL — GitHub connectors and clone credentials |
| `PEER_OAM_URL` | `` | OAM API URL — project picker (`GET /api/oam/projects?product=osa`)  With `OPA_AUTH_REQUIRED`, unset `PEER_OAM_URL` → tenant middleware **503** (no `opa.organizations` fallback). || `OSA_SECURITY_WORKSPACE` | `/workspace` | **Fallback** scan root for CI/path scans without `connector_id`/`repo_full_name` |
| `OSA_SECURITY_INGEST_TOKEN` | `` | CI ingest token for `/v1/security/*` |
| `OSA_PUBLIC_URL` | `` | Public URL for this product |
| `OSA_CVE_BUDGET` | `600` | Max OSV API requests per CVE scan |
| `OSA_CVE_HTTP_TIMEOUT_SEC` | `15` | OSV HTTP client timeout (5–120) |
| `OSA_CVE_L1_CACHE` | `20000` | In-memory CVE response cache entries |
| `OSA_RUNNER_TAG` | `smoke` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | `:8095` | Orchestrator health listen |
| `REDIS_URL` | empty | Dedicated `redis-osa` for OSV CVE L2 cache (`GET /api/security/cve/status` reports backend) |
| `OSA_SEC_KEY_PREFIX` | empty | Optional Redis key prefix (defaults to product prefix inside Open-Cache-Go) |
| `OPA_JOB_SANDBOX` | `off` | Set `docker` on NAS to run gitleaks inside `osa-runner-scan` with curated env (Open-Job-Env-Go) |

## GitHub App / PAT setup

GitHub credentials live in **ORA**, not OSA:

1. Configure the GitHub App or PAT on `ora-api` (`OPA_GITHUB_APP_*` / connector PAT bootstrap). See ORA docs.
2. Set `PEER_ORA_URL` and shared `OPEN_SERVICE_JWT_SECRET` on `osa-api`.
3. Set `PEER_OPA_URL` so OSA can list hub organizations for the tenant picker.
4. In OSA-Dashboard: pick hub org → pick ORA connector → pick `owner/repo` → start scan.

Ephemeral clones use `POST` to ORA `/api/peer/scm/clone-credentials` with service JWT `iss=osa-api`, `aud=ora-api`, scope `scm:clone`.

## SCM checker peer (`POST /api/peer/scm/events`)

ORA fans out GitHub PR/push envelopes to compatible products. OSA implements checker **`dependencies`**: lockfile-only CVE scan via OSV when `changed_paths` includes a dependency lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, Python lock/requirements pins, `go.sum`).

| Field | Notes |
|-------|-------|
| Auth | Service JWT `iss=ora-api`, `aud=osa-api`, scope **`scm:events`** |
| Trigger | `pull_request.*`, `push.default`, or default-branch `push` |
| Checks filter | Respects `checks` array — runs only when `osa:dependencies` (or bare `dependencies`) is listed |
| Dispatch | When `dispatch` is true (default), creates a `security_runs` row and starts the `cve` scanner asynchronously |

Response shape:

```json
{
  "product": "osa",
  "checkers": [{
    "id": "dependencies",
    "check_run_name": "OSA Dependencies",
    "should_run": true,
    "reason": "dependency lockfile changed: package-lock.json",
    "security_run_id": "srun-…",
    "status": "dispatched"
  }]
}
```

The `cve` scanner is also available on manual runs via `scanners: ["cve"]` (aliases: `dependencies`, `deps`, `osv`). It never reads manifest-only files (`package.json`, `composer.json`, `go.mod`).
