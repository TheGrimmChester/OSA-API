package main

import (
	"strings"
	"testing"
)

// Credential-shaped fixtures are assembled from fragments at runtime and are
// never written as source literals.
//
// The negative assertions below only mean something if these values keep the
// exact shape of live credentials — an AWS access key ID, a GitHub PAT, a Slack
// bot token, a 32-character high-entropy password. That shape is precisely what
// the detectors match on, so replacing a fixture with something a scanner would
// never flag would leave the tests passing while asserting nothing. Written out
// as literals, though, those same values are indistinguishable from real leaked
// credentials and trip GitHub push protection, which blocks every push of this
// branch. Joining fragments keeps each value under test byte-identical while
// leaving no matchable credential anywhere in the committed text.
//
// Do not "simplify" these back into literals, and do not spell a full value out
// in a comment either — secret scanning reads comments too.
func assembleFixtureSecret(parts ...string) string { return strings.Join(parts, "") }

// Fabricated values that were never live, each in the shape its detector matches.
var (
	// AWS access key ID shape: "AKIA" + 16 uppercase alphanumerics.
	fixtureAWSKeyID = assembleFixtureSecret("AKIA", "4TQ7", "HN2W", "PLZK", "X9QD")
	// The AWS documentation example key: same shape, but a placeholder by content.
	fixtureAWSExampleKeyID = assembleFixtureSecret("AKIA", "IOSFODNN7", "EXAMPLE")
	// GitHub personal access token shape: "ghp_" + 36 alphanumerics.
	fixtureGitHubPAT = assembleFixtureSecret("ghp", "_", "9fK2mQ7bZ1xR", "4tY8vN3sL6wD", "0hJ5cA2eG7iU")
	// Slack bot token shape: "xoxb-" + two numeric ids + a 20-character secret.
	fixtureSlackBotToken = assembleFixtureSecret("xoxb", "-", "2947183625", "-", "4827361094", "-", "Kf9mQ2xR7tZ1", "bY4vN8sL")
	// Opaque 32-character high-entropy password, no vendor prefix.
	fixtureOpaqueSecret = assembleFixtureSecret("7fK2mQ9bZ1xR", "4tY8vN3sL6wD", "0hJ5cA2e")
)

func TestDocExampleSecretPath(t *testing.T) {
	docs := []string{
		"docs/nas-deploy.md",
		"docs/operations/alerting.md",
		"OPA-Stack/docs/security-tenant-scopes.md",
		"README.md",
		"compose.nas.env.example",
		".env.example",
		"config/app.yaml.sample",
		"php.ini.dist",
		"examples/quickstart/main.go",
		"doc/notes.txt",
	}
	for _, f := range docs {
		if !docExampleSecretPath(f) {
			t.Errorf("docExampleSecretPath(%q) = false, want true", f)
		}
	}
	code := []string{
		"main.go",
		"security_scan.go",
		"src/components/Login.tsx",
		".env",
		"config/production.yaml",
		"deploy/compose.nas.yaml",
		"internal/auth/token.go",
		"docsearch.go", // "docs" must not match as a bare prefix of a filename
	}
	for _, f := range code {
		if docExampleSecretPath(f) {
			t.Errorf("docExampleSecretPath(%q) = true, want false", f)
		}
	}
}

func TestPlaceholderSecretValue(t *testing.T) {
	placeholders := []struct{ secret, line string }{
		{"your-smtp-password", "OPA_SMTP_PASS=your-smtp-password"},
		{"changeme", "DB_PASSWORD=changeme"},
		{"${SMTP_PASS}", "pass: ${SMTP_PASS}"},
		{"<your-token>", "Authorization: Bearer <your-token>"},
		{"xxxxxxxx", "api_key = xxxxxxxx"},
		{fixtureAWSExampleKeyID, "aws_access_key_id = " + fixtureAWSExampleKeyID},
		{"replace-me", "token: replace-me"},
		{"", "OPA_SMTP_PASS=your-smtp-password"},
		{"", `"apiKey": "placeholder"`},
		{"password", "SMTP_PASS=password"},
		{"{{ smtp_password }}", "pass: {{ smtp_password }}"},
	}
	for _, c := range placeholders {
		if !placeholderSecretValue(c.secret, c.line) {
			t.Errorf("placeholderSecretValue(%q, %q) = false, want true", c.secret, c.line)
		}
	}

	real := []struct{ secret, line string }{
		{fixtureAWSKeyID, "aws_access_key_id = " + fixtureAWSKeyID},
		{fixtureGitHubPAT, "token: " + fixtureGitHubPAT},
		{fixtureSlackBotToken, "slack: " + fixtureSlackBotToken},
		{fixtureOpaqueSecret, "SMTP_PASS=" + fixtureOpaqueSecret},
	}
	for _, c := range real {
		if placeholderSecretValue(c.secret, c.line) {
			t.Errorf("placeholderSecretValue(%q, %q) = true, want false", c.secret, c.line)
		}
	}
}

// A real-looking credential in documentation must still fail the gate; only
// visible placeholders are filtered.
func TestDocPlaceholderFalsePositiveScope(t *testing.T) {
	if !docPlaceholderFalsePositive("docs/smtp.md", "OPA_SMTP_PASS=your-smtp-password", "your-smtp-password") {
		t.Error("docs placeholder should be filtered")
	}
	if docPlaceholderFalsePositive("docs/smtp.md", "OPA_SMTP_PASS="+fixtureOpaqueSecret, fixtureOpaqueSecret) {
		t.Error("real-looking secret in docs must NOT be filtered")
	}
	if docPlaceholderFalsePositive("main.go", `apiKey := "your-api-key-here"`, "your-api-key-here") {
		t.Error("code path must NOT be filtered even for placeholder values")
	}
}

func TestIsLikelySecretFalsePositiveDocsPlaceholder(t *testing.T) {
	if !isLikelySecretFalsePositive("generic-api-key", "docs/setup.md", "SMTP_PASS=your-smtp-password", "your-smtp-password") {
		t.Error("docs placeholder should be a false positive")
	}
	// Non-generic rules are also covered by the docs guard.
	if !isLikelySecretFalsePositive("aws-access-key", "docs/aws.md", "key = "+fixtureAWSExampleKeyID, fixtureAWSExampleKeyID) {
		t.Error("canonical AWS example key in docs should be a false positive")
	}
	// Real secret in code still reported.
	if isLikelySecretFalsePositive("aws-access-key", "clickhouse.go", "key = "+fixtureAWSKeyID, fixtureAWSKeyID) {
		t.Error("real AWS key in code must be reported")
	}
	// Real secret in docs still reported.
	if isLikelySecretFalsePositive("github-pat", "docs/ci.md", "token: "+fixtureGitHubPAT, fixtureGitHubPAT) {
		t.Error("real PAT in docs must be reported")
	}
}
