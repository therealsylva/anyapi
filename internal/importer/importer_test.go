package importer

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therealsylva/anyapi/internal/model"
)

func TestSanitizedRemoteLocationDropsCredentialsAndQuery(t *testing.T) {
	parsed, err := url.Parse("https://user:secret@example.test/spec.yaml?token=top-secret#part")
	if err != nil {
		t.Fatal(err)
	}
	if got := sanitizedRemoteLocation(parsed); got != "https://example.test/spec.yaml" {
		t.Fatalf("sanitized location = %q", got)
	}
}

func fixture(t *testing.T, parts ...string) Source {
	t.Helper()
	pathParts := append([]string{"..", "..", "testdata"}, parts...)
	path := filepath.Join(pathParts...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return Source{Location: path, Data: data, BaseDir: filepath.Dir(path)}
}

func TestCurlImportRedactsEverySecret(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), fixture(t, "curl", "create-user.txt"), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Commands) != 1 || len(result.Document.Auth) != 2 {
		t.Fatalf("unexpected import: %#v", result.Document)
	}
	encoded, _ := json.Marshal(result.Document)
	text := string(encoded)
	for _, secret := range []string{"sk_test_should_be_removed", "secret-token", "do-not-compile"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q remained in document: %s", secret, text)
		}
	}
	command := result.Document.Commands[0]
	if command.Operation.Path != "/v1/users/{user_id}" || !command.Body.Fields[1].Sensitive {
		t.Fatalf("unexpected command: %#v", command)
	}
}

func TestCurlGetDataBecomesQueryParameters(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl -G --data-urlencode 'q=hello world' -d 'page=2' https://example.test/search`), Options{Format: "curl", Name: "search"})
	if err != nil {
		t.Fatal(err)
	}
	command := result.Document.Commands[0]
	if command.Operation.Method != "GET" || command.Body != nil {
		t.Fatalf("unexpected operation: %#v", command.Operation)
	}
	values := map[string]any{}
	for _, parameter := range command.Parameters {
		values[parameter.Name] = parameter.Default
	}
	if values["q"] != "hello world" || values["page"] != "2" {
		t.Fatalf("query defaults were not preserved: %#v", values)
	}
}

func TestCurlRepeatedCookiesProduceOneRuntimeFlag(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl -b 'first=secret' -b 'second=secret' https://example.test/users`), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	command := result.Document.Commands[0]
	count := 0
	for _, parameter := range command.Parameters {
		if parameter.Flag == "cookie" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("got %d cookie flags: %#v", count, command.Parameters)
	}
	if result.Document.HasErrors() {
		t.Fatalf("imported document is invalid: %#v", result.Document.Validate())
	}
}

func TestCurlRepeatedParametersAreConsolidated(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl -H 'Accept: application/json' -H 'Accept: application/problem+json' -F 'tag=one' -F 'tag=two' 'https://example.test/users/{id}/{id}'`), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Document.HasErrors() {
		t.Fatalf("consolidated document is invalid: %#v", result.Document.Validate())
	}
	command := result.Document.Commands[0]
	parameterCounts := map[string]int{}
	for _, parameter := range command.Parameters {
		parameterCounts[strings.ToLower(parameter.Name)]++
	}
	if parameterCounts["id"] != 1 || parameterCounts["accept"] != 1 {
		t.Fatalf("repeated parameters were not consolidated: %#v", command.Parameters)
	}
	if command.Body == nil || len(command.Body.Fields) != 1 || command.Body.Fields[0].Type != "array" {
		t.Fatalf("repeated multipart field was not consolidated: %#v", command.Body)
	}
}

func TestCurlBodyFileBecomesExplicitRuntimeInput(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl --data-binary @payload.json -H 'Content-Type: application/json' https://example.test/users`), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	body := result.Document.Commands[0].Body
	if body == nil || body.Example != nil || len(body.Fields) != 0 || !body.Required {
		t.Fatalf("body file was not converted to an explicit runtime input: %#v", body)
	}
}

func TestCurlUnsupportedValueOptionDoesNotStealRequestURL(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl --cert client.pem --proxy https://proxy.example.test https://api.example.test/users`), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Document.Servers["production"].URL; got != "https://api.example.test" {
		t.Fatalf("request URL was misparsed: %q", got)
	}
}

func TestImportRenamesReservedRuntimeCommand(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl https://example.test/about`), Options{Format: "curl", Name: "service"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Document.HasErrors() || result.Document.Commands[0].Path[0] != "api-about" {
		t.Fatalf("reserved command root was not repaired: %#v", result.Document.Commands[0])
	}
}

func TestCurlAuthSchemeCollisionsRemainCommandLocal(t *testing.T) {
	source := InlineSource("curl -H 'X-API-Key: first-secret' https://one.example.test/users\ncurl 'https://two.example.test/users?x-api-key=second-secret'")
	result, err := NewRegistry().Import(context.Background(), source, Options{Format: "curl", Name: "service"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Auth) != 2 || len(result.Document.Commands) != 2 || result.Document.Commands[0].Auth[0] == result.Document.Commands[1].Auth[0] {
		t.Fatalf("conflicting authentication schemes were overwritten: %#v", result.Document.Auth)
	}
	first := result.Document.Auth[result.Document.Commands[0].Auth[0]]
	second := result.Document.Auth[result.Document.Commands[1].Auth[0]]
	if first.Env == second.Env {
		t.Fatalf("colliding schemes reused one environment variable: %#v", result.Document.Auth)
	}
}

func TestCurlURLCredentialsNeverReachDocumentOrDiagnostics(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl 'http://alice-private-login:super-secret@example.test/users?access_token=sk_private'`), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result.Document)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice-private-login", "super-secret", "sk_private"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("URL credential %q remained in document: %s", secret, encoded)
		}
	}
}

func TestCurlFormDefaultsAreExecutableAndSecretsAreRequired(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), InlineSource(`curl -d 'name=Ada&password=hunter2' https://example.test/users`), Options{Format: "curl", Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	body := result.Document.Commands[0].Body
	if body == nil || len(body.Fields) != 2 {
		t.Fatalf("unexpected form body: %#v", body)
	}
	fields := map[string]model.Parameter{}
	for _, field := range body.Fields {
		fields[field.Name] = field
	}
	if fields["name"].Default != "Ada" {
		t.Fatalf("safe form default was not preserved: %#v", fields["name"])
	}
	if fields["password"].Default != nil || !fields["password"].Sensitive || !fields["password"].Required {
		t.Fatalf("secret form field was not redacted: %#v", fields["password"])
	}
}

func TestOpenAPIImportResolvesReferences(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), fixture(t, "openapi", "petstore.yaml"), Options{Format: "openapi"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Commands) != 2 {
		t.Fatalf("got %d commands", len(result.Document.Commands))
	}
	create, ok := result.Document.Command("pets.create")
	if !ok || create.Body == nil || len(create.Body.Fields) != 2 || !create.Body.Fields[1].Required && !create.Body.Fields[0].Required {
		t.Fatalf("request body reference was not resolved: %#v", create)
	}
	get, ok := result.Document.Command("pets.get")
	if !ok || len(get.Auth) != 1 || get.Parameters[0].Name != "petId" {
		t.Fatalf("unexpected GET import: %#v", get)
	}
}

func TestOpenAPIImportResolvesRelativeServerAndAllOf(t *testing.T) {
	base, err := url.Parse("https://specs.example.test/contracts/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	source := InlineSource(`openapi: 3.1.0
info: {title: Composed, version: 1.0.0}
servers: [{url: /v2}]
components:
  schemas:
    Identity:
      type: object
      required: [id]
      properties:
        id: {type: string}
    User:
      allOf:
        - {$ref: "#/components/schemas/Identity"}
        - type: object
          required: [name]
          properties:
            name: {type: string}
paths:
  /users:
    post:
      operationId: users.create
      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/User"}
      responses:
        "201": {description: Created}
`)
	source.URL = base
	result, err := NewRegistry().Import(context.Background(), source, Options{Format: "openapi"})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Document.Servers["production"].URL; got != "https://specs.example.test/v2" {
		t.Fatalf("resolved server = %q", got)
	}
	body := result.Document.Commands[0].Body
	if body == nil || len(body.Fields) != 2 || !body.Fields[0].Required || !body.Fields[1].Required {
		t.Fatalf("allOf schema was not flattened: %#v", body)
	}
}

func TestOpenAPIImportRejectsUnsupportedVersion(t *testing.T) {
	_, err := NewRegistry().Import(context.Background(), InlineSource("openapi: 4.0.0\ninfo: {title: Future}\npaths: {}\n"), Options{Format: "openapi"})
	if err == nil || !strings.Contains(err.Error(), "unsupported OpenAPI version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAPIImportReportsExternalReferences(t *testing.T) {
	source := InlineSource(`openapi: 3.1.0
info: {title: External, version: 1.0.0}
servers: [{url: https://api.example.test}]
paths:
  /users:
    post:
      operationId: createUser
      requestBody:
        content:
          application/json:
            schema: {$ref: schemas.yaml#/$defs/User}
      responses:
        "204": {description: Created}
`)
	result, err := NewRegistry().Import(context.Background(), source, Options{Format: "openapi"})
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "openapi.ref-external" {
			return
		}
	}
	t.Fatalf("missing external reference diagnostic: %#v", result.Diagnostics)
}

func TestOpenAPIImportRedactsDefaultsAndExamples(t *testing.T) {
	source := InlineSource(`openapi: 3.1.0
info: {title: Secret Example, version: 1.0.0}
servers: [{url: https://api.example.test}]
paths:
  /sessions:
    post:
      operationId: sessions.create
      parameters:
        - name: access_token
          in: query
          schema: {type: string, default: sk_should_not_survive}
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                password: {type: string, example: hunter2}
            example: {username: ada, password: hunter2}
      responses:
        "200": {description: OK}
`)
	result, err := NewRegistry().Import(context.Background(), source, Options{Format: "openapi"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result.Document)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sk_should_not_survive", "hunter2"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("secret %q remained in document: %s", secret, encoded)
		}
	}
}

func TestOpenAPIImportRedactsServerCredentials(t *testing.T) {
	source := InlineSource(`openapi: 3.1.0
info: {title: Server Secrets, version: 1.0.0}
servers:
  - url: https://user:password@example.test/v1?access_token=secret#fragment
  - url: https://api.example.test/{api_token}
    variables:
      api_token: {default: sk_server_secret}
paths:
  /status:
    get:
      operationId: status.get
      responses:
        "200": {description: OK}
`)
	result, err := NewRegistry().Import(context.Background(), source, Options{Format: "openapi"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result.Document)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{"user", "password", "access_token", "sk_server_secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("server credential %q remained in document: %s", secret, text)
		}
	}
	if result.Document.HasErrors() {
		t.Fatalf("sanitized server document is invalid: %#v", result.Document.Validate())
	}
}

func TestPostmanImportPreservesVariablesAndRedactsSecrets(t *testing.T) {
	result, err := NewRegistry().Import(context.Background(), fixture(t, "postman", "users.postman_collection.json"), Options{Format: "postman"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Commands) != 2 {
		t.Fatalf("got %d commands", len(result.Document.Commands))
	}
	get, ok := result.Document.Command("users.get")
	if !ok || get.Operation.Path != "/v2/users/{userId}" || len(get.Parameters) < 2 {
		t.Fatalf("unexpected Postman GET: %#v", get)
	}
	encoded, _ := json.Marshal(result.Document)
	text := string(encoded)
	for _, secret := range []string{"secret-test-token", "never-compile-this"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q remained in document", secret)
		}
	}
}

func TestSupportedFixturesProduceExecutableDocuments(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		format string
	}{
		{name: "curl", source: fixture(t, "curl", "create-user.txt"), format: "curl"},
		{name: "openapi", source: fixture(t, "openapi", "petstore.yaml"), format: "openapi"},
		{name: "postman", source: fixture(t, "postman", "users.postman_collection.json"), format: "postman"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NewRegistry().Import(context.Background(), test.source, Options{Format: test.format})
			if err != nil {
				t.Fatal(err)
			}
			if diagnostics := result.Document.Validate(); result.Document.HasErrors() {
				t.Fatalf("supported fixture produced an invalid document: %#v", diagnostics)
			}
		})
	}
}

func TestAutoDetection(t *testing.T) {
	for _, source := range []Source{fixture(t, "curl", "create-user.txt"), fixture(t, "openapi", "petstore.yaml"), fixture(t, "postman", "users.postman_collection.json")} {
		if _, err := NewRegistry().Import(context.Background(), source, Options{Format: "auto"}); err != nil {
			t.Fatalf("auto-detect %s: %v", source.Location, err)
		}
	}
}

func FuzzCurlImporter(f *testing.F) {
	f.Add("curl https://example.test/users/{id}")
	f.Add("curl -X POST -H 'Content-Type: application/json' -d '{\"x\":1}' https://example.test")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = (CurlImporter{}).Import(context.Background(), InlineSource(input), Options{Name: "fuzz"})
	})
}

func FuzzStructuredImporters(f *testing.F) {
	f.Add(uint8(0), []byte("openapi: 3.1.0\ninfo: {title: Fuzz}\npaths: {}\n"))
	f.Add(uint8(1), []byte(`{"info":{"name":"Fuzz","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[]}`))
	f.Fuzz(func(t *testing.T, selector uint8, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		source := Source{Location: "fuzz", Data: data}
		if selector%2 == 0 {
			_, _ = (OpenAPIImporter{}).Import(context.Background(), source, Options{Name: "fuzz"})
			return
		}
		_, _ = (PostmanImporter{}).Import(context.Background(), source, Options{Name: "fuzz"})
	})
}
