package model

import (
	"reflect"
	"strings"
	"testing"
)

func validDocument() Document {
	return Document{
		APIVersion:    APIVersion,
		Kind:          KindAPI,
		Metadata:      Metadata{Name: "example", Version: "1.0.0"},
		Servers:       map[string]Server{"production": {URL: "https://api.example.test"}},
		DefaultServer: "production",
		Commands: []Command{{
			ID: "users.get", Path: []string{"users", "get"},
			Operation:  Operation{Transport: "http", Method: "GET", Path: "/users/{id}"},
			Parameters: []Parameter{{Name: "id", Flag: "id", In: "path", Type: "string", Required: true, Positional: true}},
		}},
	}
}

func TestValidateAcceptsValidDocument(t *testing.T) {
	document := validDocument()
	if diagnostics := document.Validate(); len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
}

func TestValidateRejectsReservedAndDuplicateCommands(t *testing.T) {
	document := validDocument()
	document.Commands = append(document.Commands, document.Commands[0])
	document.Commands[0].Path = []string{"auth", "get"}
	diagnostics := document.Validate()
	codes := map[string]bool{}
	for _, diagnostic := range diagnostics {
		codes[diagnostic.Code] = true
	}
	for _, expected := range []string{"command.path-reserved", "command.id-duplicate"} {
		if !codes[expected] {
			t.Fatalf("missing diagnostic %s in %#v", expected, diagnostics)
		}
	}
}

func TestNormalizeIsDeterministic(t *testing.T) {
	document := Document{Metadata: Metadata{Name: "My Useful API"}, Servers: map[string]Server{"z": {URL: "https://z.test"}, "a": {URL: "https://a.test"}}, Auth: map[string]AuthScheme{"key": {Type: "APIKEY", In: "HEADER"}}, Commands: []Command{{Path: []string{"Users", "Get"}, Operation: Operation{Method: "get", Path: "/users"}}}}
	document.Normalize()
	if document.Metadata.Name != "my-useful-api" || document.DefaultServer != "a" || document.Commands[0].ID != "users.get" || document.Commands[0].Operation.Method != "GET" || document.Auth["key"].Type != "apiKey" || document.Auth["key"].In != "header" {
		t.Fatalf("unexpected normalized document: %#v", document)
	}
}

func TestValidateRejectsUnsafeAndUnexecutableContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Document)
		code   string
	}{
		{
			name: "server credentials",
			mutate: func(document *Document) {
				document.Servers["production"] = Server{URL: "https://user:secret@example.test"}
			},
			code: "server.credentials",
		},
		{
			name: "unsupported authentication",
			mutate: func(document *Document) {
				document.Auth = map[string]AuthScheme{}
				document.Auth["certificate"] = AuthScheme{Type: "mutualTLS"}
			},
			code: "auth.type",
		},
		{
			name: "missing path parameter",
			mutate: func(document *Document) {
				document.Commands[0].Parameters = nil
			},
			code: "operation.path-parameter-missing",
		},
		{
			name: "sensitive default",
			mutate: func(document *Document) {
				document.Commands[0].Parameters = append(document.Commands[0].Parameters, Parameter{Name: "X-Token", Flag: "token", In: "header", Type: "string", Sensitive: true, Default: "secret"})
			},
			code: "parameter.sensitive-default",
		},
		{
			name: "invalid serialization style",
			mutate: func(document *Document) {
				document.Commands[0].Parameters[0].Style = "deepObject"
			},
			code: "parameter.style",
		},
		{
			name: "environment-backed path default",
			mutate: func(document *Document) {
				document.Commands[0].Parameters[0].Default = "${USER_ID}"
			},
			code: "parameter.path-env-default",
		},
		{
			name: "invalid header name",
			mutate: func(document *Document) {
				document.Commands[0].Parameters = append(document.Commands[0].Parameters, Parameter{Name: "Bad Header", Flag: "bad-header", In: "header", Type: "string"})
			},
			code: "parameter.wire-name",
		},
		{
			name: "sensitive body example",
			mutate: func(document *Document) {
				document.Commands[0].Body = &RequestBody{ContentType: "application/json", Example: map[string]any{"password": "hunter2"}}
			},
			code: "body.example-sensitive",
		},
		{
			name: "credential-like raw body example",
			mutate: func(document *Document) {
				document.Commands[0].Body = &RequestBody{ContentType: "text/plain", Example: "Authorization: Bearer compiled-secret"}
			},
			code: "body.example-sensitive",
		},
		{
			name: "conflicting body paths",
			mutate: func(document *Document) {
				document.Commands[0].Body = &RequestBody{Fields: []Parameter{
					{Name: "profile", Flag: "profile", In: "body", Type: "object", JSONPath: "profile"},
					{Name: "name", Flag: "name", In: "body", Type: "string", JSONPath: "profile.name"},
				}}
			},
			code: "body.json-path-conflict",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validDocument()
			test.mutate(&document)
			for _, diagnostic := range document.Validate() {
				if diagnostic.Code == test.code {
					return
				}
			}
			t.Fatalf("missing diagnostic %s: %#v", test.code, document.Validate())
		})
	}
}

func TestNormalizeMarksCredentialNamedParametersSensitive(t *testing.T) {
	document := validDocument()
	document.Commands[0].Body = &RequestBody{Fields: []Parameter{{Name: "password", In: "body"}}}
	document.Normalize()
	if !document.Commands[0].Body.Fields[0].Sensitive {
		t.Fatal("credential-named body field was not marked sensitive")
	}
}

func TestValidateAllowsMultipleOptionalPositionals(t *testing.T) {
	document := validDocument()
	document.Commands[0].Operation.Path = "/search"
	document.Commands[0].Parameters = []Parameter{
		{Name: "query", Flag: "query", In: "query", Type: "string", Positional: true},
		{Name: "page", Flag: "page", In: "query", Type: "integer", Positional: true},
	}
	if diagnostics := document.Validate(); len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
}

func TestClonePreservesDynamicValueTypesAndIsolation(t *testing.T) {
	document := validDocument()
	large := int64(9_007_199_254_740_993)
	document.Commands[0].Parameters[0].Default = large
	document.Commands[0].Parameters[0].Example = map[string]any{"nested": []any{large}}
	cloned := document.Clone()
	if !reflect.DeepEqual(cloned.Commands[0].Parameters[0].Default, large) {
		t.Fatalf("default changed type or value: %#v", cloned.Commands[0].Parameters[0].Default)
	}
	cloned.Commands[0].Parameters[0].Example.(map[string]any)["nested"].([]any)[0] = int64(1)
	original := document.Commands[0].Parameters[0].Example.(map[string]any)["nested"].([]any)[0]
	if original != large {
		t.Fatalf("clone mutation changed original: %#v", original)
	}
}

func TestValidateExpandsServerVariableDefaults(t *testing.T) {
	document := validDocument()
	document.Servers["production"] = Server{URL: "https://{region}.example.test/v1", Variables: map[string]string{"region": "eu"}}
	if diagnostics := document.Validate(); len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
}

func TestNormalizeRemovesTerminalControlCharactersFromDescriptions(t *testing.T) {
	document := validDocument()
	document.Metadata.Description = "safe\x1b[31m red\u202e hidden\nnext"
	document.Commands[0].Summary = "get\x07 user"
	document.Normalize()
	if strings.ContainsAny(document.Metadata.Description, "\x1b\u202e") || strings.ContainsRune(document.Commands[0].Summary, '\x07') {
		t.Fatalf("control characters remained: %#v", document.Metadata)
	}
	if !strings.Contains(document.Metadata.Description, "\nnext") {
		t.Fatalf("safe newline was removed: %q", document.Metadata.Description)
	}
}

func TestNormalizeKeepsInlineMetadataOnOneLine(t *testing.T) {
	document := validDocument()
	document.Metadata.Version = "1.0\nforged"
	document.Metadata.Source = "spec\tfile"
	document.Normalize()
	if strings.ContainsAny(document.Metadata.Version+document.Metadata.Source, "\r\n\t") {
		t.Fatalf("inline metadata retained line controls: %#v", document.Metadata)
	}
}
