# Install

```bash
go build -o osa-api .
./osa-api                  # control plane :8093
./osa-api orchestrator     # osa-orchestrator
```

## Images

```bash
docker build --target osa-api -t osa-api:smoke .
docker build --target osa-orchestrator -t osa-orchestrator:smoke .
docker build --target osa-runner-scan -t osa-runner-scan:smoke .
```

Production / NAS: tag and deploy `*:nas` only (never `*:smoke` on NAS).
