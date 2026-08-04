# Changelog

## Unreleased

- Bootstrap OSA ClickHouse product tables (`security_runs`, findings, vulns, IAST, dependencies) in `CLICKHOUSE_DB` at startup so co-deployed `opa.*` → `osa.*` rewrite no longer hits an empty database.
- Auth via Open-Auth-Go `Gate` (delete local `auth.go` / `auth_local.go` duplicates).
- Hub-linked GitHub security targets: discover orgs via `PEER_OPA_URL`, connectors/repos via `PEER_ORA_URL`, ephemeral `owner/repo` clones for scans.

## Unreleased

- Seed AppSec control plane: security runs/profiles, secrets/SAST/IaC/containers, vulns/IAST, AppSec gate.
- `osa-orchestrator` command and `osa-runner-scan` image stage.
- Peer service JWT probe and interop documentation.
