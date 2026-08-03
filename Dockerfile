# OSA-API — Open Security Agent control plane
FROM golang:1.22-alpine AS builder
RUN apk --no-cache add git ca-certificates
WORKDIR /app
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY gitleaks.toml ./
RUN CGO_ENABLED=0 GOOS=linux go build -o osa-api .

# Default compose target — named stage so later runners are not the default image.
FROM debian:bookworm-slim AS osa-api
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/* \
 && arch="$TARGETARCH" \
 && case "$arch" in amd64|x86_64) gl_arch=x64 ;; arm64|aarch64) gl_arch=arm64 ;; *) gl_arch=x64 ;; esac \
 && wget -qO /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm -f /tmp/gitleaks.tgz \
 && test -x /usr/local/bin/gitleaks
WORKDIR /root/
COPY --from=builder /app/osa-api .
COPY gitleaks.toml /etc/opa/gitleaks.toml
COPY scripts/ /opt/osa/scripts/
ENV LISTEN_ADDR=:8093 \
    OPA_JOB_SANDBOX=off \
    OSA_RUNNER_TAG=smoke
EXPOSE 8093
CMD ["./osa-api"]

# Orchestrator uses the same binary with `orchestrator` command.
FROM osa-api AS osa-orchestrator
ENV ORCHESTRATOR_LISTEN_ADDR=:8095
CMD ["./osa-api", "orchestrator"]

# Ephemeral scan runner — one container per security run (not an always-on service).
FROM debian:bookworm-slim AS osa-runner-scan
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/* \
 && arch="$TARGETARCH" \
 && case "$arch" in amd64|x86_64) gl_arch=x64 ;; arm64|aarch64) gl_arch=arm64 ;; *) gl_arch=x64 ;; esac \
 && wget -qO /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm -f /tmp/gitleaks.tgz \
 && test -x /usr/local/bin/gitleaks
COPY gitleaks.toml /etc/opa/gitleaks.toml
USER 65532:65532
WORKDIR /home/opa
CMD ["sleep", "infinity"]
