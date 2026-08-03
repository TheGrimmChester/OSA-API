# Optional micro-services

Phase 1–2 ship a single `osa-api` process. Operators may later peel domains behind a product gateway without changing dashboard URLs.

## Target layout

```text
osa-gateway          # terminates TLS / routes /api/*
  ├── osa-inventory  # secrets/SAST/IaC/vulns/IAST query + ingest
  ├── osa-runs       # security runs / profiles / scanners
  └── osa-gate       # AppSec CI gate
osa-orchestrator     # remains the job owner
osa-runner-scan      # ephemeral; one container per run
```

Compose sketch (not required for smoke):

```yaml
# comments only — enable when services are peeled
# osa-gateway:
#   image: osa-gateway:nas
#   ports: ["8093:8093"]
# osa-inventory:
#   image: osa-inventory:nas
# osa-runs:
#   image: osa-runs:nas
# osa-gate:
#   image: osa-gate:nas
```

Until peeled, point all traffic at `osa-api:8093`. Gateway stubs must not introduce legacy path aliases.
