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

### `GET /api/security/runs` — list query params

| Param | Default | Range | Notes |
|-------|---------|-------|-------|
| `limit` | `50` | `1`–`200` | Values above `200` are **silently clamped** to `200`. There is no `offset` or cursor; the handler returns the most recent rows by `started_at DESC` for the active tenant only. |

Response shape: `{"runs":[…],"workspace":"…"}`. No `total`, `has_more`, or `limit_applied` metadata — clients cannot page past the cap without a future API change.

Tenant headers **`X-Organization-ID`** / **`X-Project-ID`** scope lists when `OPA_AUTH_REQUIRED=1` (NAS). Omitting them (or sending `"all"`) scopes to **`default-org` / `default-project`**, matching writes (Open-Tenant-Go ≥ 0.2.2). Same pattern applies to inventory routes such as `GET /api/security/secrets` and `GET /api/security/sast`.

**NAS example** (hub JWT; no headers → default-org rows; wrong org → empty; `limit=500` still capped at 200):

```bash
TOKEN=$(curl -sf -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .token)

curl -sf "http://127.0.0.1:8093/api/security/runs?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.runs | length'

curl -sf "http://127.0.0.1:8093/api/security/runs?limit=500" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Organization-ID: default-org" \
  -H "X-Project-ID: default-project" | jq '.runs | length'   # → ≤200

curl -sf "http://127.0.0.1:8093/api/security/runs?limit=5" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Organization-ID: no-such-org" \
  -H "X-Project-ID: no-such-project" | jq '.runs | length'   # → 0
```

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

## Peer-callable AppSec routes

These accept **either** a user JWT (viewer+) or a service JWT (`aud=osa-api`) minted
with `OPEN_SERVICE_JWT_SECRET`. `ora-api` calls them to delegate AppSec; every other
route is user-JWT-only.

| Route | Read scope | Write scope |
| --- | --- | --- |
| `/api/security/runs` | `findings:read` | `runs:write` |
| `/api/security/runs/{id}` | `findings:read` | `runs:write` |
| `/api/security/gate` | `findings:read` | `findings:read` (POST is a read) |

A service JWT presented to a user-only route fails `ParseUserJWT` and returns
**401 `invalid token`** — matching secrets on both sides do not help. If `ora-api`
logs `peer OSA security run failed` / `peer OSA gate failed` with that 401, check
this wiring before suspecting secret drift.
