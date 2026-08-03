# Install

## Local smoke (laptop)

Build and run the `osa-api:smoke` image on a developer machine only.

```bash
docker build -t osa-api:smoke .
docker run --rm -p 8093:8093 osa-api:smoke
```

## Production / NAS

Use `osa-api:nas` image tags only. Never deploy `*:smoke` to production hosts.
