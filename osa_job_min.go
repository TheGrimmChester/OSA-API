package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	openjob "github.com/TheGrimmChester/open-job-go"
	openjobenv "github.com/TheGrimmChester/open-job-env-go"
)

type jobPhase string

const jobPhaseScan jobPhase = "scan"

type jobEnvSpec struct {
	Phase        jobPhase
	WorktreeRoot string
	Extra        map[string]string
	Secrets      map[string]string
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
	Extra       map[string]string
	Secrets     map[string]string
}

var errSandboxNotWired = errors.New("osa docker sandbox not wired; use host scanners or osa-orchestrator")

func sandboxImageForPhase(phase jobPhase) string {
	_ = phase
	tag := envOr("OSA_RUNNER_TAG", "nas")
	if tag == "smoke" {
		tag = "nas"
	}
	return openjob.RunnerImage("osa", "scan", tag)
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

func redactJobOutput(raw []byte, secrets ...string) []byte {
	out := raw
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if len(s) < 8 {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(s), []byte("***"))
	}
	for _, name := range []string{"JWT_SECRET", "OPEN_SERVICE_JWT_SECRET", "CLICKHOUSE_URL", "REDIS_URL"} {
		if v := strings.TrimSpace(os.Getenv(name)); len(v) >= 8 {
			out = bytes.ReplaceAll(out, []byte(v), []byte("***"))
		}
	}
	return out
}

func runSandboxedArgv(ctx context.Context, spec sandboxExecSpec) ([]byte, error) {
	if sandboxMode() != "docker" {
		return nil, errSandboxNotWired
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker CLI not found: %w", err)
	}
	hostDir := filepath.Clean(spec.HostWorkDir)
	if !filepath.IsAbs(hostDir) {
		return nil, fmt.Errorf("HostWorkDir must be absolute")
	}
	image := strings.TrimSpace(spec.Image)
	if image == "" {
		image = sandboxImageForPhase(spec.Phase)
	}
	net := strings.TrimSpace(spec.Network)
	if net == "" {
		net = "none"
	}
	envFile, err := writeSandboxEnvFile(spec)
	if err != nil {
		return nil, err
	}
	defer os.Remove(envFile)

	name := "osa-job-" + sanitizeDockerName(spec.JobID)
	labels := openjob.Labels{Product: "osa", JobID: spec.JobID, Instance: envOr("OSA_INSTANCE", "default")}
	base := openjob.DockerRunArgv(image, labels, map[string]string{"CI": "true"})
	args := []string{"run", "--rm", "--name", name}
	if len(base) > 1 {
		args = append(args, base[1:]...)
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--network" {
			args[i+1] = net
			break
		}
	}
	args = insertDockerArgBeforeImage(args, image, "-v", hostDir+":/scan"+roSuffix(spec.ReadOnly))
	if spec.OutHostDir != "" {
		args = insertDockerArgBeforeImage(args, image, "-v", filepath.Clean(spec.OutHostDir)+":/out:rw")
	}
	if envFile != "" {
		args = insertDockerArgBeforeImage(args, image, "--env-file", envFile)
	}
	args = append(args, spec.Argv...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func writeSandboxEnvFile(spec sandboxExecSpec) (string, error) {
	lines := openjobenv.JobEnv(openjobenv.Spec{
		Phase:        openjobenv.Phase(spec.Phase),
		WorktreeRoot: spec.HostWorkDir,
		Extra:        spec.Extra,
		Secrets:      spec.Secrets,
	})
	f, err := os.CreateTemp("", "osa-sandbox-env-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	for _, line := range lines {
		if openjobenv.EnvNameLooksSecret(strings.SplitN(line, "=", 2)[0]) {
			continue
		}
		if _, err := fmt.Fprintln(f, line); err != nil {
			f.Close()
			os.Remove(path)
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, os.Chmod(path, 0o600)
}

func roSuffix(readOnly bool) string {
	if readOnly {
		return ":ro"
	}
	return ":rw"
}

func insertDockerArgBeforeImage(args []string, image string, extra ...string) []string {
	out := make([]string, 0, len(args)+len(extra))
	inserted := false
	for _, a := range args {
		if !inserted && a == image {
			out = append(out, extra...)
			inserted = true
		}
		out = append(out, a)
	}
	if !inserted {
		out = append(out, extra...)
	}
	return out
}

func sanitizeDockerName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "scan"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func sandboxMode() string {
	return openjobenv.SandboxModeFromEnv()
}

func jobEnv(spec jobEnvSpec) []string {
	return openjobenv.JobEnv(openjobenv.Spec{
		Phase:   openjobenv.Phase(spec.Phase),
		Extra:   spec.Extra,
		Secrets: spec.Secrets,
	})
}
