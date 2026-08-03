# Interop

Products are optional peers. Empty peer URLs disable cross-product features (respond `peer_unavailable` / skip — never require the whole family at boot).

| Variable | Purpose |
|----------|---------|
| `PEER_OPA_URL` | OPA hub base URL — tenancy/org discovery + co-deployed auth when `AUTH_MODE` unset |
| `PEER_ORA_URL` | ORA API base URL — GitHub App/PAT connectors and clone credentials |
| `PEER_OSA_URL` | This product (rarely set on self) |
| `PEER_OPL_URL` | OPL API base URL |
| `OPEN_SERVICE_JWT_SECRET` | Service JWT mint/validate (prefer distinct from `JWT_SECRET`) |
| `JWT_SECRET` | User JWT secret |
| `AUTH_MODE` | `standalone` (local `/api/auth/login`) or `codeployed` (hub-issued tokens) |
| `CLICKHOUSE_DB` | ClickHouse database for this product (default `osa`) |
| `OSA_PUBLIC_URL` | Public base URL for this product |

## Hub-linked GitHub model

OSA does **not** store GitHub App private keys or PATs. Discovery and credentials follow the same pattern as OPM:

```mermaid
flowchart LR
  UI[osa-dashboard] --> API[osa-api]
  API -->|tenancy orgs| Hub[opa-hub]
  API -->|connectors list-repos| ORA[ora-api]
  API -->|service JWT scm:clone| ORA
  ORA -->|short-lived token| API
  API -->|tmp clone owner/repo| Tmp[/tmp/osa-scan-*]
```

1. **Hub** (`PEER_OPA_URL`): identity and organization directory (`GET /api/tenancy/organizations`, `GET /api/github/status`).
2. **ORA** (`PEER_ORA_URL`): GitHub App / PAT connectors; list repos; mint short-lived clone credentials.
3. **OSA**: proxies discovery for the dashboard; security runs with `connector_id` + `repo_full_name` (`owner/repo`) clone into an ephemeral directory, scan, then delete the clone.

Dashboard calls only `osa-api`. Peer calls are server-side.

## User auth modes

| Mode | Behavior |
|------|----------|
| **Standalone** | `osa-api` issues JWTs locally. Lab admin: `admin`/`admin`. |
| **Co-deployed** | Share `JWT_SECRET` with **OPA-Hub**; hub issues; `osa-api` validates. |

## Service JWT

Mint with `Open-Auth-Go` / `Open-Client-Go` peer helpers: claims `iss` (caller), `aud` (callee), `sub=service`, `scope`, short `exp`, optional `org_id`.

| Caller → Callee | Scopes |
|-----------------|--------|
| ORA → OSA | `runs:write`, `findings:read`, `health:read` |
| OSA → ORA | `connectors:read` (optional; dashboard usually forwards user JWT), `scm:clone`, `health:read` |
| OSA → OPA hub | `health:read` (optional probe) |

| Scope | Meaning |
|-------|---------|
| `findings:read` | Read AppSec findings / run summaries (ORA → OSA) |
| `runs:write` | Create/link security run from review (ORA → OSA) |
| `scm:clone` | Request short-lived clone credentials from ORA |
| `connectors:read` | List ORA connectors / repos as a peer service |
| `traces:read` | Trace metadata for correlation (OSA → OPA) |
| `health:read` | Peer probe |

Browser clients never hold `OPEN_SERVICE_JWT_SECRET`.
