package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
)

// Minimal job helpers for host-mode scanners. Full docker sandbox for
// osa-runner-scan is owned by osa-orchestrator (Open-Job-Go labels).

type jobPhase string

const jobPhaseScan jobPhase = "scan"

type jobEnvSpec struct {
	Phase   jobPhase
	Extra   map[string]string
	Secrets map[string]string
}

func sandboxMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPA_JOB_SANDBOX"))) {
	case "docker":
		return "docker"
	default:
		return "off"
	}
}

func jobEnv(spec jobEnvSpec) []string {
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/opa",
		"LANG=C.UTF-8",
	}
	for k, v := range spec.Extra {
		if k == "" {
			continue
		}
		env = append(env, k+"="+v)
	}
	return env
}

func redactJobOutput(raw []byte, secrets ...string) []byte {
	out := raw
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if len(s) < 8 {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(s), []byte("***"))
	}
	for _, name := range []string{"JWT_SECRET", "OPEN_SERVICE_JWT_SECRET", "CLICKHOUSE_URL"} {
		if v := strings.TrimSpace(os.Getenv(name)); len(v) >= 8 {
			out = bytes.ReplaceAll(out, []byte(v), []byte("***"))
		}
	}
	return out
}

type sandboxExecSpec struct {
	Phase       jobPhase
	JobID       string
	LayoutID    string
	NetworkID   string
	HostWorkDir string
	WorkRel     string
	Argv        []string
	ReadOnly    bool
	Network     string
	Image       string
	Ephemeral   bool
	OutHostDir  string
}

func sandboxImageForPhase(phase jobPhase) string {
	_ = phase
	tag := envOr("OSA_RUNNER_TAG", "smoke")
	return "osa-runner-scan:" + tag
}

func resolveSandboxJobID(preferred, root string) string {
	if strings.TrimSpace(preferred) != "" {
		return preferred
	}
	_ = root
	return "osa-scan"
}

func sandboxWorkRel(root string) string {
	_ = root
	return "primary"
}

var errSandboxNotWired = errors.New("osa docker sandbox not wired; use host scanners or osa-orchestrator")

func runSandboxedArgv(ctx context.Context, spec sandboxExecSpec) ([]byte, error) {
	_ = ctx
	_ = spec
	return nil, errSandboxNotWired
}
