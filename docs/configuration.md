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
| `OSA_SECURITY_WORKSPACE` | `/workspace` | **Fallback** scan root for CI/path scans without `connector_id`/`repo_full_name` |
| `OSA_SECURITY_INGEST_TOKEN` | `` | CI ingest token for `/v1/security/*` |
| `OSA_PUBLIC_URL` | `` | Public URL for this product |
| `OSA_RUNNER_TAG` | `smoke` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | `:8095` | Orchestrator health listen |
| `OPA_JOB_SANDBOX` | `off` | Set `docker` when orchestrator spawns `osa-runner-scan` |

## GitHub App / PAT setup

GitHub credentials live in **ORA**, not OSA:

1. Configure the GitHub App or PAT on `ora-api` (`OPA_GITHUB_APP_*` / connector PAT bootstrap). See ORA docs.
2. Set `PEER_ORA_URL` and shared `OPEN_SERVICE_JWT_SECRET` on `osa-api`.
3. Set `PEER_OPA_URL` so OSA can list hub organizations for the tenant picker.
4. In OSA-Dashboard: pick hub org → pick ORA connector → pick `owner/repo` → start scan.

Ephemeral clones use `POST` to ORA `/api/peer/scm/clone-credentials` with service JWT `iss=osa-api`, `aud=ora-api`, scope `scm:clone`.
