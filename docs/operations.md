# Operations

## Health

Probe `GET /api/health` on `osa-api`.

## Logs

Structured JSON logs on stdout. Collect via the container runtime.

## Upgrades

Roll the `osa-api:nas` image. Keep ClickHouse migrations versioned and applied before cutting traffic.
