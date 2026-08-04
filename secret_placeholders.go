package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Documentation and example-configuration placeholders are published guidance,
// not credentials. A gate that fails on `OPA_SMTP_PASS=your-smtp-password` in a
// docs page teaches reviewers to ignore it, so the next real leak is ignored too.
//
// Filtering is deliberately narrow: it needs BOTH a documentation/example path
// AND a value that is visibly a placeholder. A real-looking credential committed
// to docs still fails the gate, and nothing here relaxes detection in code.

// docExampleSecretPath reports whether file is documentation or an example
// configuration template rather than a deployed artifact.
func docExampleSecretPath(file string) bool {
	file = filepath.ToSlash(strings.ToLower(strings.TrimSpace(file)))
	if file == "" {
		return false
	}
	base := filepath.Base(file)

	// Example/template configuration: .env.example, compose.nas.env.example,
	// config.yaml.sample, php.ini.dist …
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".tpl"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	// …and the inverted spelling (example.env, sample.config).
	for _, prefix := range []string{"example.", "sample.", "template."} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}

	// Prose documentation.
	for _, ext := range []string{".md", ".mdx", ".markdown", ".rst", ".adoc", ".txt"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}

	// Documentation trees, at any depth.
	for _, seg := range []string{"docs/", "doc/", "documentation/", "examples/", "example/", "samples/"} {
		if strings.HasPrefix(file, seg) || strings.Contains(file, "/"+seg) {
			return true
		}
	}
	return false
}

// placeholderMarkers are substrings that mark a value as a stand-in. Matched
// case-insensitively against the value only — never against the whole line, so
// a real secret on a line mentioning "example" is still reported.
var placeholderMarkers = []string{
	"your-", "your_", "yourorg", "yourdomain", "youruser",
	"changeme", "change-me", "change_me",
	"replaceme", "replace-me", "replace_me", "replace-with",
	"placeholder", "example", "sample", "dummy", "redacted", "notreal",
	"todo", "fixme", "insert-", "insert_", "fill-in", "fill_in",
	"my-secret", "my_secret", "supersecret", "hunter2",
	"xxxx", "abcd1234", "1234567890", "0123456789",
	"deadbeef", "s3cr3t", "letmein",
}

// placeholderExactValues are whole values that only name the field they fill.
var placeholderExactValues = map[string]bool{
	"password": true, "passwd": true, "pass": true, "secret": true,
	"apikey": true, "api_key": true, "api-key": true, "token": true,
	"key": true, "credential": true, "credentials": true, "value": true,
	"string": true, "none": true, "null": true, "nil": true, "empty": true,
	"test": true, "testing": true, "demo": true, "local": true, "dev": true,
	"admin": true, "user": true, "username": true, "root": true,
}

// templateRef matches values that are substitutions rather than literals:
// ${VAR}, $VAR, {{ var }}, <your-token>, %s, __VALUE__.
var templateRef = regexp.MustCompile(`^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{[^}]*\}\}|<[^>]*>|%[sdv]|__[A-Za-z0-9_]+__)$`)

// repeatedCharValue reports masked stand-ins such as xxxxxxxx, ********, ......
// RE2 has no backreferences, so this is a scan rather than a pattern.
func repeatedCharValue(v string) bool {
	if len(v) < 4 {
		return false
	}
	first := v[0]
	for i := 1; i < len(v); i++ {
		if v[i] != first {
			return false
		}
	}
	return true
}

// assignedValue extracts the right-hand side of a KEY=value / "key": "value"
// pair so the lite scanner (which passes a whole line) can be evaluated on the
// value alone.
var assignedValue = regexp.MustCompile(`[:=]\s*['"\x60]?([^'"\x60\s,;]+)`)

// placeholderSecretValue reports whether the detected value is visibly a
// stand-in. secret is the detector's extracted value; line is the surrounding
// text used only to recover a value when secret is empty.
func placeholderSecretValue(secret, line string) bool {
	v := strings.TrimSpace(secret)
	if v == "" {
		m := assignedValue.FindStringSubmatch(line)
		if len(m) < 2 {
			return false
		}
		v = strings.TrimSpace(m[1])
	}
	v = strings.Trim(v, `'"`+"`")
	if v == "" {
		return true
	}
	if templateRef.MatchString(v) || repeatedCharValue(v) {
		return true
	}
	lower := strings.ToLower(v)
	if placeholderExactValues[lower] {
		return true
	}
	// Angle/brace wrapped anywhere: <token>, ${SMTP_PASS}
	if strings.ContainsAny(v, "<>{}") {
		return true
	}
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// docPlaceholderFalsePositive is the combined guard used by the scanners.
func docPlaceholderFalsePositive(file, match, secret string) bool {
	return docExampleSecretPath(file) && placeholderSecretValue(secret, match)
}
