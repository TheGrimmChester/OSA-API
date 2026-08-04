# Security

- **Standalone:** issue and validate user JWTs with this product's `JWT_SECRET` (`POST /api/auth/login`).
- **Co-deployed:** validate hub-issued JWTs with a shared `JWT_SECRET`; do not use local login as the identity home.
- Service-to-service calls use short-lived JWTs minted with `OPEN_SERVICE_JWT_SECRET` (distinct from user secret when possible).
- Enforce `X-Organization-ID` / `X-Project-ID` tenancy on control-plane routes. When `OPA_AUTH_REQUIRED=1`, omitting those headers (or sending `"all"`) scopes ClickHouse lists to `default-org` / `default-project` (HTTP 200; Open-Tenant-Go ≥ 0.2.2). Hub-minted `project_ids` are enforced via Open-Auth-Go `EnforceProjectACL` (non-member project → **403**; role `admin` unrestricted).
- Job containers must not inherit `JWT_SECRET`, service JWTs, or connector secrets.
- Store AppSec data in the `osa` ClickHouse database (`CLICKHOUSE_DB`), not a shared `opa` schema.
