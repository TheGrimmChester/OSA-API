# API

Smoke listen address: `:8093`. Health `service` id: `osa-api`.

## Health

`GET /api/health` → `{"status":"ok","service":"osa-api"}`

## Security runs

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/security/profiles` | Scanner profiles (`auto`, `php`, `node`, …) |
| GET/POST | `/api/security/runs` | List / create security runs |
| GET | `/api/security/runs/{id}` | Run detail |
| GET | `/api/security/runs/{id}/findings` | Findings for a run |

## AppSec inventory + ingest

| Method | Path |
|--------|------|
| GET | `/api/security/secrets` |
| GET | `/api/security/sast` |
| GET | `/api/security/iac` |
| GET | `/api/security/containers` |
| GET | `/api/security/policies` |
| POST | `/v1/security/secrets` |
| POST | `/v1/security/sast` |
| POST | `/v1/security/iac` |
| POST | `/v1/security/containers` |

CI ingest uses `OSA_SECURITY_INGEST_TOKEN` via `Authorization: Bearer` or `X-OSA-Security-Token`.

## AppSec gate

| Method | Path |
|--------|------|
| GET/POST | `/api/security/gate` | Fail-closed on secrets/SAST/IaC severity for `security_run_id` |

Distinct from ORA **review** check-runs.

## Vulns / IAST

| Method | Path |
|--------|------|
| POST | `/v1/sbom` |
| GET | `/api/vulns/summary` |
| GET | `/api/vulns/findings` |
| GET | `/api/vulns/inventory` |
| GET | `/api/iast/summary` |
| GET | `/api/iast/findings` |

## Peer probe

`GET /api/peer/health` — validates service JWT (`aud=osa-api`, scope `health:read`) when `OPEN_SERVICE_JWT_SECRET` is set.
