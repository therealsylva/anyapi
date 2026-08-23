package runtimecli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/therealsylva/anyapi/internal/model"
)

func TestReadSecretFromStdinPreservesWhitespace(t *testing.T) {
	value, err := readSecret(IO{In: strings.NewReader("  secret value  \r\n")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if value != "  secret value  " {
		t.Fatalf("secret whitespace changed: %q", value)
	}
}

func TestReadSecretFromStdinEnforcesLimit(t *testing.T) {
	_, err := readSecret(IO{In: bytes.NewReader(bytes.Repeat([]byte{'x'}, (1<<20)+1))}, true)
	if err == nil {
		t.Fatal("expected oversized secret to fail")
	}
}

func TestRuntimeRenamesFlagsThatCollideWithBuiltins(t *testing.T) {
	document := &model.Document{
		Metadata: model.Metadata{Name: "collision"},
		Commands: []model.Command{{
			ID: "users.create", Path: []string{"users", "create"},
			Operation:  model.Operation{Transport: "http", Method: "POST", Path: "/users"},
			Parameters: []model.Parameter{{Name: "server", Flag: "server", In: "query", Type: "string"}},
			Body:       &model.RequestBody{ContentType: "application/json", Fields: []model.Parameter{{Name: "body", Flag: "body", In: "body", Type: "string"}}},
		}},
	}
	document.Normalize()
	var output bytes.Buffer
	root := New(document, "test", IO{In: strings.NewReader(""), Out: &output, Err: &output})
	root.SetArgs([]string{"users", "create", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "--parameter-server") || !strings.Contains(output.String(), "--body-body") {
		t.Fatalf("collision-safe flags missing from help:\n%s", output.String())
	}
}

func TestRuntimeErrorsUseCollisionSafeFlagName(t *testing.T) {
	document := &model.Document{
		Metadata:      model.Metadata{Name: "collision"},
		Servers:       map[string]model.Server{"production": {URL: "https://example.test"}},
		DefaultServer: "production",
		Commands: []model.Command{{
			ID: "users.list", Path: []string{"users", "list"},
			Operation:  model.Operation{Transport: "http", Method: "GET", Path: "/users"},
			Parameters: []model.Parameter{{Name: "server", Flag: "server", In: "query", Type: "string", Required: true}},
		}},
	}
	document.Normalize()
	var output bytes.Buffer
	root := New(document, "test", IO{In: strings.NewReader(""), Out: &output, Err: &output})
	root.SetArgs([]string{"users", "list", "--dry-run"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "--parameter-server") {
		t.Fatalf("collision-safe error missing: %v", err)
	}
}

func TestValidOutputMode(t *testing.T) {
	for _, value := range []string{"auto", "raw", "json", "yaml", "table", "JSON"} {
		if !validOutputMode(value) {
			t.Fatalf("valid output mode %q was rejected", value)
		}
	}
	if validOutputMode("xml") {
		t.Fatal("unsupported output mode was accepted")
	}
}
