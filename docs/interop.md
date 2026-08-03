# Interop

Products are optional peers. Empty peer URLs disable cross-product features (respond `peer_unavailable` / skip — never require the whole family at boot).

| Variable | Purpose |
|----------|---------|
| `PEER_OPA_URL` | OPA hub base URL (optional deep links) |
| `PEER_ORA_URL` | ORA API base URL |
| `PEER_OSA_URL` | This product (rarely set on self) |
| `PEER_OPL_URL` | OPL API base URL |
| `OPEN_SERVICE_JWT_SECRET` | Service JWT mint/validate (prefer distinct from `JWT_SECRET`) |
| `JWT_SECRET` | User JWT validation |
| `OSA_PUBLIC_URL` | Public base URL for this product |

## Service JWT

Mint with `Open-Auth-Go`: claims `iss` (caller), `aud` (callee), `sub=service`, `scope`, short `exp`, optional `org_id`.

| Scope | Meaning |
|-------|---------|
| `findings:read` | Read AppSec findings / run summaries (ORA → OSA) |
| `runs:write` | Create/link security run from review (ORA → OSA) |
| `traces:read` | Trace metadata for correlation (OSA → OPA) |
| `health:read` | Peer probe |

Dashboards call only `osa-api`. Peer calls are server-side.
