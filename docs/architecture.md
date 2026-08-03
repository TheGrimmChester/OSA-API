# Architecture

`osa-api` is the HTTP control plane for Open Security Agent. Async security runs are scheduled by `osa-orchestrator` into ephemeral `osa-runner-scan` containers (one container per run).

```mermaid
flowchart LR
  UI[osa-dashboard] --> API[osa-api]
  API --> Orch[osa-orchestrator]
  Orch --> Runner[osa-runner-scan]
  API --> CH[(ClickHouse)]
  API -->|orgs / identity| Hub[opa-hub]
  API -->|connectors + clone creds| ORA[ora-api]
  ORA -.->|optional peer findings| API
```

## Security targets

Primary UX: **hub org → ORA GitHub connector → `owner/repo`**. OSA clones the repo into a temporary directory for the scan job, then removes it. There is no durable local project registry.

`OSA_SECURITY_WORKSPACE` remains a **fallback** for CI path ingest and lab mounts when `connector_id` / `repo_full_name` are omitted.

## Ownership

| Surface | Product |
|---------|---------|
| Secrets / SAST / IaC / container findings | OSA |
| Security runs / profiles | OSA |
| Vulns / IAST / SBOM ingest | OSA |
| AppSec CI gate | OSA |
| Hub identity / tenancy directory | OPA-Hub |
| GitHub App / PAT connectors | ORA |
| Review check-runs / Repo Watch | ORA (not OSA) |

## Containers

| Image | Role |
|-------|------|
| `osa-api` | Control plane (`:8093`) |
| `osa-orchestrator` | Same binary, `orchestrator` command — job lifecycle / reaper |
| `osa-runner-scan` | Ephemeral gitleaks/lite scanner box (not always-on) |

Image tags: `*:smoke` (laptop) · `*:nas` (production / NAS only).

## Optional micro-services (Phase 3)

Behind an optional `osa-gateway`, the plane may later split into `osa-inventory`, `osa-runs`, and `osa-gate`. Until then, all routes live on `osa-api`. See [microservices.md](microservices.md).
