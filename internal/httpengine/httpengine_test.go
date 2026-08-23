package httpengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therealsylva/anyapi/internal/model"
)

func TestExecuteBuildsTypedAuthenticatedRequest(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/users/usr_1" || request.URL.Query().Get("verbose") != "true" {
			t.Errorf("unexpected URL %s", request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer token-value" {
			t.Errorf("unexpected auth header %q", request.Header.Get("Authorization"))
		}
		data, _ := io.ReadAll(request.Body)
		_ = json.Unmarshal(data, &received)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	document := &model.Document{Metadata: model.Metadata{Name: "users", Version: "1"}, Servers: map[string]model.Server{"production": {URL: server.URL + "/v1"}}, DefaultServer: "production", Auth: map[string]model.AuthScheme{"token": {Type: "bearer", Env: "USERS_TOKEN"}}}
	command := &model.Command{ID: "users.update", Path: []string{"users", "update"}, Operation: model.Operation{Transport: "http", Method: "PATCH", Path: "/users/{id}"}, Parameters: []model.Parameter{{Name: "id", Flag: "id", In: "path", Type: "string", Required: true}, {Name: "verbose", Flag: "verbose", In: "query", Type: "boolean"}}, Body: &model.RequestBody{Required: true, ContentType: "application/json", Fields: []model.Parameter{{Name: "age", Flag: "age", In: "body", Type: "integer", Required: true, JSONPath: "age"}}}, Auth: []string{"token"}}
	document.Commands = []model.Command{*command}
	document.Normalize()
	t.Setenv("USERS_TOKEN", "token-value")
	response, err := Execute(context.Background(), document, &document.Commands[0], Input{Values: map[string][]string{"id": {"usr_1"}, "verbose": {"true"}}, BodyValues: map[string][]string{"age": {"7"}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || received["age"] != float64(7) {
		t.Fatalf("unexpected response/body: %#v %#v", response, received)
	}
}

func TestExecuteRetriesIdempotentTransientFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	document := &model.Document{Metadata: model.Metadata{Name: "retry"}, Servers: map[string]model.Server{"production": {URL: server.URL}}, DefaultServer: "production"}
	command := &model.Command{ID: "ping", Path: []string{"ping"}, Operation: model.Operation{Transport: "http", Method: "GET", Path: "/ping"}}
	response, err := Execute(context.Background(), document, command, Input{}, Options{Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("retry failed: status=%d calls=%d", response.StatusCode, calls.Load())
	}
}

func TestPrepareNeverPrintsAuthInDryRun(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "safe"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production", Auth: map[string]model.AuthScheme{"token": {Type: "bearer", Env: "SAFE_TOKEN"}}}
	command := &model.Command{ID: "ping", Path: []string{"ping"}, Operation: model.Operation{Transport: "http", Method: "GET", Path: "/ping"}, Auth: []string{"token"}}
	t.Setenv("SAFE_TOKEN", "top-secret")
	prepared, err := Prepare(document, command, Input{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prepared.Headers.Get("Authorization"), "top-secret") {
		t.Fatal("auth was not applied internally")
	}
}

func TestPrepareExpandsServerVariables(t *testing.T) {
	document := &model.Document{
		Metadata:      model.Metadata{Name: "variable"},
		Servers:       map[string]model.Server{"production": {URL: "https://{region}.example.test/{version}", Variables: map[string]string{"region": "eu", "version": "v2"}}},
		DefaultServer: "production",
	}
	command := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/status"}}
	prepared, err := Prepare(document, command, Input{}, Options{NoAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.URL != "https://eu.example.test/v2/status" {
		t.Fatalf("expanded URL = %q", prepared.URL)
	}
}

func TestLimitedBufferRejectsOverflow(t *testing.T) {
	buffer := limitedBuffer{max: 4}
	if _, err := buffer.Write([]byte("four")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("!")); !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("overflow error = %v", err)
	}
}

func TestPrepareSerializesOpenAPIStyles(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "styles"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	explode := true
	command := &model.Command{
		Operation: model.Operation{Transport: "http", Method: "GET", Path: "/points/{coordinates}"},
		Parameters: []model.Parameter{
			{Name: "coordinates", Flag: "coordinates", In: "path", Type: "array", Style: "label", Explode: &explode, Required: true},
			{Name: "filter", Flag: "filter", In: "query", Type: "object", Style: "deepObject"},
			{Name: "tags", Flag: "tags", In: "query", Type: "array", Style: "pipeDelimited"},
			{Name: "X-Meta", Flag: "x-meta", In: "header", Type: "object", Style: "simple", Explode: &explode},
		},
	}
	prepared, err := Prepare(document, command, Input{Values: map[string][]string{
		"coordinates": {"10", "20"},
		"filter":      {`{"z":"last","a":"first"}`},
		"tags":        {"one", "two"},
		"X-Meta":      {`{"trace":"abc","level":2}`},
	}}, Options{NoAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(prepared.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EscapedPath() != "/points/.10.20" {
		t.Fatalf("serialized path = %q", parsed.EscapedPath())
	}
	if parsed.Query().Get("filter[a]") != "first" || parsed.Query().Get("filter[z]") != "last" || parsed.Query().Get("tags") != "one|two" {
		t.Fatalf("serialized query = %q", parsed.RawQuery)
	}
	if prepared.Headers.Get("X-Meta") != "level=2,trace=abc" {
		t.Fatalf("serialized header = %q", prepared.Headers.Get("X-Meta"))
	}
}

func TestPrepareRejectsInvalidObjectParameter(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "objects"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	command := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/search"}, Parameters: []model.Parameter{{Name: "filter", Flag: "filter", In: "query", Type: "object", Style: "deepObject"}}}
	_, err := Prepare(document, command, Input{Values: map[string][]string{"filter": {"not-json"}}}, Options{NoAuth: true})
	if err == nil {
		t.Fatal("expected invalid object parameter to fail")
	}
}

func TestExecuteRejectsUnsafeRuntimeBounds(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "bounds"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	command := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/status"}}
	tests := []Options{
		{DryRun: true, Retries: maxRetries + 1},
		{DryRun: true, MaxResponse: hardMaxResponse + 1},
		{DryRun: true, Timeout: -time.Second},
	}
	for _, options := range tests {
		if _, err := Execute(context.Background(), document, command, Input{}, options); err == nil {
			t.Fatalf("unsafe options were accepted: %#v", options)
		}
	}
}

func TestPrepareRejectsCredentialsInServerOverride(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "server"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	command := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/status"}}
	_, err := Prepare(document, command, Input{}, Options{Server: "https://user:secret@example.test"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe server error = %v", err)
	}
}

func TestExplicitValuesAreNotEnvironmentExpanded(t *testing.T) {
	t.Setenv("ANYAPI_LITERAL_TEST", "expanded")
	document := &model.Document{Metadata: model.Metadata{Name: "literal"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	command := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/search"}, Parameters: []model.Parameter{{Name: "query", Flag: "query", In: "query", Type: "string"}}}
	prepared, err := Prepare(document, command, Input{Values: map[string][]string{"query": {"${ANYAPI_LITERAL_TEST}"}}}, Options{NoAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(prepared.URL)
	if parsed.Query().Get("query") != "${ANYAPI_LITERAL_TEST}" {
		t.Fatalf("explicit value was expanded: %q", parsed.Query().Get("query"))
	}
}

func TestImportedJSONExampleIsMergedWithRuntimeSecrets(t *testing.T) {
	document := &model.Document{
		Metadata:      model.Metadata{Name: "users"},
		Servers:       map[string]model.Server{"production": {URL: "https://example.test"}},
		DefaultServer: "production",
		Import:        &model.ImportMetadata{Format: "curl"},
	}
	document.Commands = []model.Command{{
		ID: "users.create", Path: []string{"users", "create"},
		Operation: model.Operation{Transport: "http", Method: "POST", Path: "/users"},
		Body: &model.RequestBody{
			ContentType: "application/json",
			Required:    true,
			Example:     map[string]any{"username": "Ada", "password": nil},
			Fields: []model.Parameter{
				{Name: "username", Flag: "username", In: "body", Type: "string", JSONPath: "username"},
				{Name: "password", Flag: "password", In: "body", Type: "string", JSONPath: "password", Sensitive: true, Required: true},
			},
		},
	}}
	document.Normalize()
	prepared, err := Prepare(document, &document.Commands[0], Input{BodyValues: map[string][]string{"password": {"runtime-secret"}}}, Options{NoAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(prepared.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["username"] != "Ada" || body["password"] != "runtime-secret" {
		t.Fatalf("imported example was not merged: %#v", body)
	}
}

func TestPrepareRejectsInvalidHeaderControlsAndCookieValues(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "safe"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	headerCommand := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/"}}
	if _, err := Prepare(document, headerCommand, Input{}, Options{NoAuth: true, Headers: []string{"X-Test: safe\x1b[31m"}}); err == nil {
		t.Fatal("header control character was accepted")
	}
	cookieCommand := &model.Command{Operation: model.Operation{Transport: "http", Method: "GET", Path: "/"}, Parameters: []model.Parameter{{Name: "session", Flag: "session", In: "cookie", Type: "string"}}}
	if _, err := Prepare(document, cookieCommand, Input{Values: map[string][]string{"session": {"bad;value"}}}, Options{NoAuth: true}); err == nil {
		t.Fatal("invalid cookie value was accepted")
	}
}

func TestEnvironmentBackedDefaultsAreMarkedSensitive(t *testing.T) {
	t.Setenv("ANYAPI_QUERY_VALUE", "query-secret")
	t.Setenv("ANYAPI_BODY_VALUE", "body-secret")
	document := &model.Document{Metadata: model.Metadata{Name: "defaults"}, Servers: map[string]model.Server{"production": {URL: "https://example.test"}}, DefaultServer: "production"}
	command := &model.Command{
		Operation:  model.Operation{Transport: "http", Method: "POST", Path: "/users"},
		Parameters: []model.Parameter{{Name: "filter", Flag: "filter", In: "query", Type: "string", Default: "${ANYAPI_QUERY_VALUE}"}},
		Body:       &model.RequestBody{ContentType: "application/json", Fields: []model.Parameter{{Name: "note", Flag: "note", In: "body", Type: "string", Default: "${ANYAPI_BODY_VALUE}", JSONPath: "note"}}},
	}
	prepared, err := Prepare(document, command, Input{}, Options{NoAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prepared.RedactedURL(), "query-secret") || !prepared.SensitiveQuery["filter"] || len(prepared.SensitiveBody) != 1 {
		t.Fatalf("environment-backed defaults were not redacted: %#v", prepared)
	}
}
