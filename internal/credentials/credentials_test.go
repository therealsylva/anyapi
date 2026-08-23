package credentials

import (
	"errors"
	"strings"
	"testing"

	"github.com/therealsylva/anyapi/internal/model"
	"github.com/zalando/go-keyring"
)

func TestResolvePrefersEnvironment(t *testing.T) {
	t.Setenv("USERS_TOKEN", "from-environment")
	original := keyringGet
	keyringGet = func(_, _ string) (string, error) {
		t.Fatal("keyring should not be read when the environment is set")
		return "", nil
	}
	t.Cleanup(func() { keyringGet = original })
	value, err := Resolve("users", "token", model.AuthScheme{Env: "USERS_TOKEN"})
	if err != nil || value != "from-environment" {
		t.Fatalf("value=%q error=%v", value, err)
	}
}

func TestResolvePropagatesKeyringFailureWithoutLeakingSecret(t *testing.T) {
	original := keyringGet
	keyringGet = func(_, _ string) (string, error) { return "", errors.New("keyring unavailable") }
	t.Cleanup(func() { keyringGet = original })
	_, err := Resolve("users", "token", model.AuthScheme{})
	if err == nil || !strings.Contains(err.Error(), "keyring unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveReportsMissingCredential(t *testing.T) {
	original := keyringGet
	keyringGet = func(_, _ string) (string, error) { return "", keyring.ErrNotFound }
	t.Cleanup(func() { keyringGet = original })
	_, err := Resolve("users", "token", model.AuthScheme{Env: "USERS_TOKEN"})
	if !errors.Is(err, ErrMissing) || !strings.Contains(err.Error(), "USERS_TOKEN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetRejectsNULBytes(t *testing.T) {
	if err := Set("users", "basic", model.AuthScheme{Type: "basic"}, "ada", "bad\x00secret"); err == nil {
		t.Fatal("expected NUL credential to fail")
	}
}

func TestBasicCredentialsRejectAmbiguousUsername(t *testing.T) {
	if err := Set("users", "basic", model.AuthScheme{Type: "basic"}, "ada:admin", "secret"); err == nil {
		t.Fatal("expected basic-auth username containing a colon to fail")
	}
}

func TestResolveRejectsCredentialNewlines(t *testing.T) {
	t.Setenv("USERS_TOKEN", "first\nsecond")
	if _, err := Resolve("users", "token", model.AuthScheme{Env: "USERS_TOKEN"}); err == nil {
		t.Fatal("expected credential newline to fail")
	}
}
