# API

Smoke listen address: `:8093`. Health `service` id: `osa-api`.

## Health

`GET /api/health` → `{"status":"ok","service":"osa-api"}`


## Hub + GitHub discovery

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/hub/organizations` | Proxy hub tenancy orgs (`PEER_OPA_URL`) |
| GET | `/api/hub/github/status` | Hub GitHub status + OSA peer config |
| GET | `/api/github/connectors` | Proxy ORA connectors (`PEER_ORA_URL`) |
| GET | `/api/github/connectors/{id}/repos` | Proxy ORA repo list |
| GET | `/api/security/targets` | Discovery model summary for the dashboard |

## Security runs

Create body (GitHub primary):

```json
{
  "connector_id": "conn-…",
  "repo_full_name": "owner/repo",
  "ref": "main",
  "profile": "auto",
  "scanners": ["secrets", "sast"],
  "dispatch": true
}
```

`connector_id` + `repo_full_name` trigger an ephemeral clone via ORA. Omit both to fall back to `target_path` under `OSA_SECURITY_WORKSPACE`.

## Security runs

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/security/profiles` | Scanner profiles (`auto`, `php`, `node`, …) |
| GET/POST | `/api/security/runs` | List / create security runs (`connector_id` + `repo_full_name` preferred) |
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
