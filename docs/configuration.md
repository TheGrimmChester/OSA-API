# Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` / `HTTP_ADDR` | `:8093` | HTTP listen address |
| `JWT_SECRET` | `` | User JWT validation secret |
| `OPEN_SERVICE_JWT_SECRET` | `` | Service JWT mint/validate secret |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP endpoint |
| `OSA_SECURITY_WORKSPACE` | `/workspace` | Scan workspace root |
| `OSA_SECURITY_INGEST_TOKEN` | `` | CI ingest token for `/v1/security/*` |
| `PEER_OPA_URL` | `` | Optional OPA hub URL |
| `PEER_ORA_URL` | `` | Optional ORA API URL |
| `OSA_PUBLIC_URL` | `` | Public URL for this product |
| `OSA_RUNNER_TAG` | `smoke` | Runner image tag (`smoke` or `nas`) |
| `ORCHESTRATOR_LISTEN_ADDR` | `:8095` | Orchestrator health listen |
| `OPA_JOB_SANDBOX` | `off` | Set `docker` when orchestrator spawns `osa-runner-scan` |
