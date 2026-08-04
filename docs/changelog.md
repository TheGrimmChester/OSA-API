# Changelog

## Unreleased

- Secrets: scope detection so documentation and example-configuration placeholders no longer fail the gate. A match is filtered only when the path is documentation or a `*.example`-style template **and** the value is visibly a stand-in (`your-…`, `changeme`, `${VAR}`, `<token>`, `xxxx…`, or a value that only names its field). Real credentials in documentation still fail, and code paths are unchanged. Enforced in the finding ingest path (covering both the full engine and the embedded lite scanner) rather than as a `gitleaks.toml` path allowlist, which would apply unconditionally and hide real secrets committed to documentation.
- Auth: adopt Open-Auth-Go per-user project ACLs (`project_ids` / `EnforceProjectACL` on Gate middleware). Restricted JWTs get **403** on non-member `X-Project-ID`; role `admin` stays unrestricted. No second membership store — hub-minted claims only.
- Auth: `GET /api/security/runs/{id}` and findings subroutes require the same viewer JWT as the collection (previously registered without middleware).
- Bump `open-tenant-go` to v0.2.2 so auth-enforced list scope matches `WriteTenant` (`default-org` / `default-project` when headers are omitted or `"all"`).
- Docs: tenant list scope defaults (no longer empty without headers); NAS curl contrast in api/interop.
- Bootstrap OSA ClickHouse product tables (`security_runs`, findings, vulns, IAST, dependencies) in `CLICKHOUSE_DB` at startup so co-deployed `opa.*` → `osa.*` rewrite no longer hits an empty database.
- Auth via Open-Auth-Go `Gate` (delete local `auth.go` / `auth_local.go` duplicates).
- Hub-linked GitHub security targets: discover orgs via `PEER_OPA_URL`, connectors/repos via `PEER_ORA_URL`, ephemeral `owner/repo` clones for scans.

## Unreleased

- Seed AppSec control plane: security runs/profiles, secrets/SAST/IaC/containers, vulns/IAST, AppSec gate.
- `osa-orchestrator` command and `osa-runner-scan` image stage.
- Peer service JWT probe and interop documentation.
