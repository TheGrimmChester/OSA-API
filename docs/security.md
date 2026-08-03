# Security

- Validate user JWTs with `JWT_SECRET` when auth is required.
- Service-to-service calls use short-lived JWTs minted with `OPEN_SERVICE_JWT_SECRET` (distinct from user secret when possible).
- Enforce `X-Organization-ID` / `X-Project-ID` tenancy on control-plane routes.
- Job containers must not inherit `JWT_SECRET`, service JWTs, or connector secrets.
