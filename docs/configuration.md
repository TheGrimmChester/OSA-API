# Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` / `HTTP_ADDR` | `:8093` | HTTP listen address |
| `JWT_SECRET` | `` | User JWT secret (issue in standalone; validate in co-deployed) |
| `AUTH_MODE` | auto | `standalone` or `codeployed` (auto from `PEER_OPA_URL` when empty) |
| `AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` | `admin` / `admin` | Lab admin seed for standalone login |
| `OPEN_SERVICE_JWT_SECRET` | `` | Service JWT mint/validate secret |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP endpoint |
| `CLICKHOUSE_DB` | `osa` | Product database. Alias: `CLICKHOUSE_DATABASE` |
| `OSA_SECURITY_WORKSPACE` | `/workspace` | Scan workspace root |
| `OSA_SECURITY_INGEST_TOKEN` | `` | CI ingest token for `/v1/security/*` |
| `PEER_OPA_URL` | `` | Optional OPA hub URL |
| `PEER_ORA_URL` | `` | Optional ORA API URL |
| `OSA_PUBLIC_URL` | `` | Public URL for this product |
| `OSA_RUNNER_TAG` | `smoke` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | `:8095` | Orchestrator health listen |
| `OPA_JOB_SANDBOX` | `off` | Set `docker` when orchestrator spawns `osa-runner-scan` |
