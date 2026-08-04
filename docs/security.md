# Security

- **Standalone:** issue and validate user JWTs with this product's `JWT_SECRET` (`POST /api/auth/login`).
- **Co-deployed:** validate hub-issued JWTs with a shared `JWT_SECRET`; do not use local login as the identity home.
- Service-to-service calls use short-lived JWTs minted with `OPEN_SERVICE_JWT_SECRET` (distinct from user secret when possible).
- Enforce `X-Organization-ID` / `X-Project-ID` tenancy on control-plane routes. When `OPA_AUTH_REQUIRED=1`, ClickHouse list endpoints return empty arrays if those headers are omitted (HTTP 200, not 401).
- Job containers must not inherit `JWT_SECRET`, service JWTs, or connector secrets.
- Store AppSec data in the `osa` ClickHouse database (`CLICKHOUSE_DB`), not a shared `opa` schema.
