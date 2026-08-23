package config

import (
	"strings"
	"testing"
)

func TestDecodeAcceptsNonSensitiveProfile(t *testing.T) {
	file, err := decode([]byte("profiles:\n  staging:\n    server: https://staging.example.test\n    headers:\n      X-Tenant: team-a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if file.Profiles["staging"].Headers["X-Tenant"] != "team-a" {
		t.Fatalf("unexpected profile: %#v", file)
	}
}

func TestDecodeRejectsUnknownFieldsAndSensitiveHeaders(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown", "profiles: {}\nunknown: true\n", "field unknown not found"},
		{"secret", "profiles:\n  production:\n    headers:\n      X-Access-Token: secret\n", "forbidden sensitive header"},
		{"newline", "profiles:\n  production:\n    headers:\n      X-Test: |\n        first\n        second\n", "contains a newline"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decode([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
