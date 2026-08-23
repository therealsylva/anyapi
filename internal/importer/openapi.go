package importer

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/therealsylva/anyapi/internal/model"
)

type OpenAPIImporter struct{}

func (OpenAPIImporter) Name() string { return "openapi" }

func (OpenAPIImporter) Detect(source Source) int {
	root, err := decodeGeneric(source.Data)
	if err != nil {
		return 0
	}
	if stringValue(root["openapi"]) != "" {
		return 100
	}
	if stringValue(root["swagger"]) == "2.0" {
		return 100
	}
	if object(root["paths"]) != nil && object(root["info"]) != nil {
		return 60
	}
	return 0
}

func (OpenAPIImporter) Import(_ context.Context, source Source, options Options) (*Result, error) {
	root, err := decodeGeneric(source.Data)
	if err != nil {
		return nil, err
	}
	version := stringValue(root["openapi"])
	isSwagger2 := stringValue(root["swagger"]) == "2.0"
	if version == "" && !isSwagger2 {
		return nil, fmt.Errorf("missing openapi or swagger version")
	}
	if !isSwagger2 && !strings.HasPrefix(version, "3.0.") && !strings.HasPrefix(version, "3.1.") {
		return nil, fmt.Errorf("unsupported OpenAPI version %q; supported versions are 3.0.x and 3.1.x", version)
	}
	info := object(root["info"])
	title := stringValue(info["title"])
	document := &model.Document{
		APIVersion: model.APIVersion,
		Kind:       model.KindAPI,
		Metadata: model.Metadata{
			Name:        chooseName(options, title),
			Version:     stringValue(info["version"]),
			Description: stringValue(info["description"]),
		},
		Servers: map[string]model.Server{},
		Auth:    map[string]model.AuthScheme{},
	}
	var diagnostics []model.Diagnostic
	diagnostics = append(diagnostics, openAPIReferenceDiagnostics(root)...)
	if document.Metadata.Version == "" {
		document.Metadata.Version = "1.0.0"
	}
	importOpenAPIServers(root, source, document, isSwagger2, &diagnostics)
	authNames := importOpenAPIAuth(root, document, isSwagger2, &diagnostics)
	rootSecurity, rootHasSecurity := root["security"]
	paths := object(root["paths"])
	if paths == nil {
		return nil, fmt.Errorf("paths object is missing")
	}
	pathNames := sortedKeys(paths)
	methods := []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}
	for _, pathName := range pathNames {
		pathItem := resolveObject(root, paths[pathName], nil, 0)
		if pathItem == nil {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.path-invalid", Path: "paths." + pathName, Message: "path item is not an object and was skipped"})
			continue
		}
		pathParameters := list(pathItem["parameters"])
		for _, method := range methods {
			operation := resolveObject(root, pathItem[method], nil, 0)
			if operation == nil {
				continue
			}
			command, commandDiagnostics := importOpenAPIOperation(root, document, pathName, method, operation, pathParameters, isSwagger2, authNames, rootSecurity, rootHasSecurity)
			diagnostics = append(diagnostics, commandDiagnostics...)
			command = uniqueCommand(document, command, &diagnostics)
			document.Commands = append(document.Commands, command)
		}
	}
	if len(document.Commands) == 0 {
		return nil, fmt.Errorf("specification contains no supported HTTP operations")
	}
	document.Normalize()
	return &Result{Document: document, Diagnostics: diagnostics}, nil
}

func importOpenAPIServers(root map[string]any, source Source, document *model.Document, swagger2 bool, diagnostics *[]model.Diagnostic) {
	if swagger2 {
		host := stringValue(root["host"])
		basePath := stringValue(root["basePath"])
		scheme := "https"
		if schemes := list(root["schemes"]); len(schemes) > 0 {
			scheme = stringValue(schemes[0])
		}
		if host != "" {
			serverURL := strings.TrimRight(scheme+"://"+host, "/") + "/" + strings.TrimLeft(basePath, "/")
			serverURL = sanitizeImportedServerURL(serverURL, "servers.production", diagnostics)
			document.Servers["production"] = model.Server{URL: serverURL}
			document.Servers["production"] = model.Server{URL: strings.TrimRight(document.Servers["production"].URL, "/")}
			document.DefaultServer = "production"
			return
		}
	}
	servers := list(root["servers"])
	for index, raw := range servers {
		serverObject := object(raw)
		rawURL := stringValue(serverObject["url"])
		if rawURL == "" {
			continue
		}
		variables := map[string]string{}
		unsafeVariable := false
		for name, rawVariable := range object(serverObject["variables"]) {
			value := stringValue(object(rawVariable)["default"])
			if looksSensitive(name, value) {
				unsafeVariable = true
				*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: fmt.Sprintf("servers[%d].variables.%s", index, name), Message: "sensitive server variable default was removed", Hint: "replace the server URL with a credential-free base URL"})
				continue
			}
			variables[name] = value
			rawURL = strings.ReplaceAll(rawURL, "{"+name+"}", value)
		}
		name := "production"
		if index > 0 {
			name = fmt.Sprintf("server-%d", index+1)
		}
		if unsafeVariable {
			rawURL = "https://api.example.invalid"
			variables = map[string]string{}
		}
		rawURL = sanitizeImportedServerURL(rawURL, fmt.Sprintf("servers[%d]", index), diagnostics)
		parsed, err := url.Parse(rawURL)
		if err == nil && (parsed.Scheme == "" || parsed.Host == "") && source.URL != nil {
			parsed = source.URL.ResolveReference(parsed)
			rawURL = parsed.String()
		}
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			placeholderPath := "/" + strings.TrimLeft(rawURL, "/")
			rawURL = "https://api.example.invalid" + strings.TrimRight(placeholderPath, "/")
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.server-relative", Path: rawURL, Message: "relative or invalid server URL requires configuration", Hint: "replace the placeholder origin before use"})
		}
		document.Servers[name] = model.Server{URL: strings.TrimRight(rawURL, "/"), Description: stringValue(serverObject["description"]), Variables: variables}
		if document.DefaultServer == "" {
			document.DefaultServer = name
		}
	}
	if len(document.Servers) == 0 {
		document.Servers["production"] = model.Server{URL: "https://api.example.invalid", Description: "Replace with the API server URL"}
		document.DefaultServer = "production"
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.server-missing", Path: "servers", Message: "specification has no absolute server URL", Hint: "replace https://api.example.invalid before use"})
	}
}

func sanitizeImportedServerURL(rawURL, path string, diagnostics *[]model.Diagnostic) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.User != nil {
		parsed.User = nil
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: path, Message: "credentials embedded in an OpenAPI server URL were removed", Hint: "use an authentication scheme"})
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.server-query", Path: path, Message: "query parameters in an OpenAPI server URL were removed", Hint: "model them as operation parameters"})
	}
	if parsed.Fragment != "" {
		parsed.Fragment = ""
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.server-fragment", Path: path, Message: "fragment in an OpenAPI server URL was removed"})
	}
	return parsed.String()
}

func importOpenAPIAuth(root map[string]any, document *model.Document, swagger2 bool, diagnostics *[]model.Diagnostic) map[string]string {
	rawSchemes := object(root["securityDefinitions"])
	if !swagger2 {
		rawSchemes = object(object(root["components"])["securitySchemes"])
	}
	names := map[string]string{}
	for _, originalName := range sortedKeys(rawSchemes) {
		raw := resolveObject(root, rawSchemes[originalName], nil, 0)
		if raw == nil {
			continue
		}
		name := model.Slug(originalName)
		if name == "" {
			continue
		}
		typeName := strings.ToLower(stringValue(raw["type"]))
		scheme := strings.ToLower(stringValue(raw["scheme"]))
		auth := model.AuthScheme{Description: stringValue(raw["description"]), Env: model.EnvName(document.Metadata.Name, originalName)}
		switch typeName {
		case "apikey":
			auth.Type = "apiKey"
			auth.In = stringValue(raw["in"])
			auth.Name = stringValue(raw["name"])
		case "http":
			switch scheme {
			case "basic":
				auth.Type = "basic"
				auth.UsernameEnv = model.EnvName(document.Metadata.Name, originalName, "username")
				auth.PasswordEnv = model.EnvName(document.Metadata.Name, originalName, "password")
			case "bearer":
				auth.Type = "bearer"
			default:
				auth.Type = "http"
				auth.Name = scheme
				*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.auth-http", Path: originalName, Message: fmt.Sprintf("HTTP auth scheme %q requires runtime review", scheme)})
			}
		case "basic":
			auth.Type = "basic"
			auth.UsernameEnv = model.EnvName(document.Metadata.Name, originalName, "username")
			auth.PasswordEnv = model.EnvName(document.Metadata.Name, originalName, "password")
		case "oauth2", "openidconnect":
			auth.Type = "oauth2"
			auth.Name = "Bearer"
			auth.Scopes = collectOAuthScopes(raw)
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityInfo, Code: "openapi.auth-oauth-token", Path: originalName, Message: "OAuth authentication will use a pre-issued access token", Hint: "set " + auth.Env + " or use the OS keyring"})
		case "mutualtls":
			auth.Type = "mutualTLS"
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.auth-mtls", Path: originalName, Message: "mutual TLS requires certificate configuration at runtime"})
		default:
			auth.Type = typeName
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.auth-unknown", Path: originalName, Message: fmt.Sprintf("authentication type %q may require manual configuration", typeName)})
		}
		name = installAuthScheme(document, name, auth)
		names[originalName] = name
	}
	return names
}

func collectOAuthScopes(raw map[string]any) []string {
	set := map[string]struct{}{}
	for _, flow := range object(raw["flows"]) {
		for scope := range object(object(flow)["scopes"]) {
			set[scope] = struct{}{}
		}
	}
	for scope := range object(raw["scopes"]) {
		set[scope] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for scope := range set {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func importOpenAPIOperation(root map[string]any, document *model.Document, pathName, method string, operation map[string]any, pathParameters []any, swagger2 bool, authNames map[string]string, rootSecurity any, rootHasSecurity bool) (model.Command, []model.Diagnostic) {
	var diagnostics []model.Diagnostic
	operationID := stringValue(operation["operationId"])
	tags := stringList(operation["tags"])
	commandPath := openAPICommandPath(pathName, method, operationID, tags, operation["x-anyapi-command"])
	command := model.Command{
		ID:          model.SlugID(operationID),
		Path:        commandPath,
		Summary:     stringValue(operation["summary"]),
		Description: stringValue(operation["description"]),
		Operation:   model.Operation{Transport: "http", Method: strings.ToUpper(method), Path: pathName},
		Source:      &model.SourceRecord{Format: "openapi", OperationID: operationID, Pointer: "#/paths/" + escapePointer(pathName) + "/" + method},
	}
	if command.ID == "" {
		command.ID = strings.Join(command.Path, ".")
	}
	allParameters := mergeParameterLists(root, pathParameters, list(operation["parameters"]))
	for _, rawParameter := range allParameters {
		parameterObject := resolveObject(root, rawParameter, nil, 0)
		if parameterObject == nil {
			continue
		}
		location := stringValue(parameterObject["in"])
		if location == "body" && swagger2 {
			command.Body = bodyFromSchema(root, resolveObject(root, parameterObject["schema"], nil, 0), stringValue(parameterObject["description"]), "application/json", boolValue(parameterObject["required"]))
			sanitizeOpenAPIBody(command.Body, command.ID+".body", &diagnostics)
			continue
		}
		if location == "formData" && swagger2 {
			if command.Body == nil {
				contentType := firstString(operation["consumes"], firstString(root["consumes"], "multipart/form-data"))
				command.Body = &model.RequestBody{ContentType: contentType}
			}
			field := parameterFromOpenAPI(root, parameterObject, "body")
			field.JSONPath = field.Name
			sanitizeOpenAPIParameter(&field, command.ID+".body."+field.Name, &diagnostics)
			command.Body.Fields = append(command.Body.Fields, field)
			continue
		}
		parameter := parameterFromOpenAPI(root, parameterObject, location)
		sanitizeOpenAPIParameter(&parameter, command.ID+"."+parameter.Name, &diagnostics)
		if parameter.In == "path" {
			parameter.Required = true
			parameter.Positional = true
		}
		command.Parameters = append(command.Parameters, parameter)
	}
	if !swagger2 {
		requestBody := resolveObject(root, operation["requestBody"], nil, 0)
		if requestBody != nil {
			content := object(requestBody["content"])
			contentType := chooseContentType(content)
			media := object(content[contentType])
			schema := resolveObject(root, media["schema"], nil, 0)
			command.Body = bodyFromSchema(root, schema, stringValue(requestBody["description"]), contentType, boolValue(requestBody["required"]))
			if example := media["example"]; example != nil {
				command.Body.Example = example
			}
			sanitizeOpenAPIBody(command.Body, command.ID+".body", &diagnostics)
		}
	}
	security, hasOperationSecurity := operation["security"]
	if !hasOperationSecurity && rootHasSecurity {
		security = rootSecurity
	}
	command.Auth = securityNames(security, authNames, &diagnostics, command.ID)
	command.Responses = openAPIResponses(root, operation)
	return command, diagnostics
}

func sanitizeOpenAPIParameter(parameter *model.Parameter, path string, diagnostics *[]model.Diagnostic) {
	if parameter == nil {
		return
	}
	if !looksSensitive(parameter.Name, stringValue(parameter.Default)) && !looksSensitive(parameter.Name, stringValue(parameter.Example)) {
		return
	}
	parameter.Default = nil
	parameter.Example = nil
	parameter.Sensitive = true
	*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: path, Message: "sensitive OpenAPI default or example was removed", Hint: "provide it at runtime"})
}

func sanitizeOpenAPIBody(body *model.RequestBody, path string, diagnostics *[]model.Diagnostic) {
	if body == nil {
		return
	}
	if body.Example != nil {
		sanitized, redacted := sanitizeValue(body.Example, path)
		body.Example = sanitized
		for _, redactedPath := range redacted {
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: redactedPath, Message: "sensitive OpenAPI body example was removed", Hint: "provide it at runtime"})
		}
	}
	for index := range body.Fields {
		sanitizeOpenAPIParameter(&body.Fields[index], path+"."+body.Fields[index].Name, diagnostics)
	}
}

func openAPICommandPath(pathName, method, operationID string, tags []string, extension any) []string {
	switch typed := extension.(type) {
	case string:
		parts := splitCommandWords(typed)
		if len(parts) > 0 {
			return parts
		}
	case []any:
		parts := make([]string, 0, len(typed))
		for _, value := range typed {
			if slug := model.Slug(stringValue(value)); slug != "" {
				parts = append(parts, slug)
			}
		}
		if len(parts) > 0 {
			return parts
		}
	}
	if strings.ContainsAny(operationID, "/:.") {
		if parts := splitCommandWords(operationID); len(parts) > 1 {
			return parts
		}
	}
	derived := deriveHTTPCommandPath(method, pathName)
	action := ""
	if operationID != "" {
		action = camelSlug(operationID)
		if len(tags) > 0 {
			tag := model.Slug(tags[0])
			action = strings.TrimPrefix(action, tag+"-")
			action = strings.TrimSuffix(action, "-"+tag)
			if action == "" {
				action = derived[len(derived)-1]
			}
			return []string{safeRoot(tag), action}
		}
	}
	if len(tags) > 0 {
		derived[0] = safeRoot(model.Slug(tags[0]))
	}
	return derived
}

func safeRoot(value string) string {
	switch value {
	case "about", "auth", "completion", "help", "version":
		return "api-" + value
	case "":
		return "request"
	default:
		return value
	}
}

var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func camelSlug(value string) string {
	return model.Slug(camelBoundary.ReplaceAllString(value, `${1}-${2}`))
}

func splitCommandWords(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == ':' || r == '.' || r == ' ' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if slug := camelSlug(part); slug != "" {
			result = append(result, slug)
		}
	}
	return result
}

func parameterFromOpenAPI(root map[string]any, raw map[string]any, location string) model.Parameter {
	schema := resolveObject(root, raw["schema"], nil, 0)
	if schema == nil {
		schema = raw
	}
	parameter := model.Parameter{
		Name:        stringValue(raw["name"]),
		In:          location,
		Type:        stringValue(schema["type"]),
		Format:      stringValue(schema["format"]),
		Description: stringValue(raw["description"]),
		Required:    boolValue(raw["required"]),
		Default:     schema["default"],
		Example:     raw["example"],
		Enum:        list(schema["enum"]),
		Style:       stringValue(raw["style"]),
	}
	if parameter.Example == nil {
		parameter.Example = schema["example"]
	}
	if parameter.Type == "" {
		parameter.Type = "string"
	}
	if value, ok := raw["explode"].(bool); ok {
		parameter.Explode = &value
	}
	return parameter
}

func bodyFromSchema(root map[string]any, schema map[string]any, description, contentType string, required bool) *model.RequestBody {
	body := &model.RequestBody{ContentType: contentType, Description: description, Required: required}
	if schema == nil {
		return body
	}
	schema = flattenOpenAPISchema(root, schema, 0)
	if example := schema["example"]; example != nil {
		body.Example = example
	}
	requiredFields := map[string]bool{}
	for _, name := range stringList(schema["required"]) {
		requiredFields[name] = true
	}
	properties := object(schema["properties"])
	for _, name := range sortedKeys(properties) {
		property := flattenOpenAPISchema(root, resolveObject(root, properties[name], nil, 0), 0)
		if property == nil {
			continue
		}
		field := model.Parameter{
			Name:        name,
			Flag:        model.Slug(name),
			In:          "body",
			Type:        stringValue(property["type"]),
			Format:      stringValue(property["format"]),
			Description: stringValue(property["description"]),
			Required:    requiredFields[name],
			Default:     property["default"],
			Example:     property["example"],
			Enum:        list(property["enum"]),
			JSONPath:    name,
		}
		if field.Type == "" {
			field.Type = "string"
		}
		body.Fields = append(body.Fields, field)
	}
	return body
}

func flattenOpenAPISchema(root map[string]any, schema map[string]any, depth int) map[string]any {
	if schema == nil || depth > 64 {
		return schema
	}
	schema = resolveObject(root, schema, nil, depth)
	if len(list(schema["allOf"])) == 0 {
		return schema
	}
	merged := make(map[string]any, len(schema))
	properties := map[string]any{}
	required := map[string]struct{}{}
	for _, raw := range list(schema["allOf"]) {
		component := flattenOpenAPISchema(root, resolveObject(root, raw, nil, depth+1), depth+1)
		for key, value := range component {
			if key != "properties" && key != "required" && key != "allOf" {
				if _, exists := merged[key]; !exists {
					merged[key] = value
				}
			}
		}
		for name, value := range object(component["properties"]) {
			properties[name] = value
		}
		for _, name := range stringList(component["required"]) {
			required[name] = struct{}{}
		}
	}
	for key, value := range schema {
		if key != "properties" && key != "required" && key != "allOf" {
			merged[key] = value
		}
	}
	for name, value := range object(schema["properties"]) {
		properties[name] = value
	}
	for _, name := range stringList(schema["required"]) {
		required[name] = struct{}{}
	}
	if len(properties) > 0 {
		merged["properties"] = properties
	}
	if len(required) > 0 {
		names := make([]string, 0, len(required))
		for name := range required {
			names = append(names, name)
		}
		sort.Strings(names)
		values := make([]any, len(names))
		for index, name := range names {
			values[index] = name
		}
		merged["required"] = values
	}
	return merged
}

func chooseContentType(content map[string]any) string {
	if content == nil {
		return "application/json"
	}
	for _, preferred := range []string{"application/json", "application/*+json", "multipart/form-data", "application/x-www-form-urlencoded"} {
		if _, ok := content[preferred]; ok {
			return preferred
		}
	}
	keys := sortedKeys(content)
	if len(keys) > 0 {
		return keys[0]
	}
	return "application/json"
}

func openAPIResponses(root map[string]any, operation map[string]any) []model.Response {
	responses := object(operation["responses"])
	result := make([]model.Response, 0, len(responses))
	for _, status := range sortedKeys(responses) {
		response := resolveObject(root, responses[status], nil, 0)
		if response == nil {
			continue
		}
		contentType := chooseContentType(object(response["content"]))
		if object(response["content"]) == nil {
			contentType = ""
		}
		result = append(result, model.Response{Status: status, Description: stringValue(response["description"]), ContentType: contentType})
	}
	return result
}

func mergeParameterLists(root map[string]any, first, second []any) []any {
	values := map[string]any{}
	order := []string{}
	for _, source := range [][]any{first, second} {
		for _, raw := range source {
			parameter := resolveObject(root, raw, nil, 0)
			if parameter == nil {
				continue
			}
			key := stringValue(parameter["in"]) + ":" + stringValue(parameter["name"])
			if _, exists := values[key]; !exists {
				order = append(order, key)
			}
			values[key] = raw
		}
	}
	result := make([]any, 0, len(order))
	for _, key := range order {
		result = append(result, values[key])
	}
	return result
}

func securityNames(raw any, authNames map[string]string, diagnostics *[]model.Diagnostic, path string) []string {
	requirements := list(raw)
	if len(requirements) == 0 {
		return nil
	}
	if len(requirements) > 1 {
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.auth-alternatives", Path: path, Message: "multiple alternative security requirements were reduced to the first alternative", Hint: "review command authentication"})
	}
	first := object(requirements[0])
	keys := sortedKeys(first)
	result := make([]string, 0, len(keys))
	for _, original := range keys {
		if mapped := authNames[original]; mapped != "" {
			result = append(result, mapped)
		} else {
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.auth-undefined", Path: path, Message: fmt.Sprintf("security requirement %q has no imported scheme", original), Hint: "define the scheme under components.securitySchemes"})
		}
	}
	return result
}

func resolveObject(root map[string]any, raw any, seen map[string]bool, depth int) map[string]any {
	if depth > 64 {
		return nil
	}
	value := object(raw)
	if value == nil {
		return nil
	}
	ref := stringValue(value["$ref"])
	if ref == "" || !strings.HasPrefix(ref, "#/") {
		return value
	}
	if seen == nil {
		seen = map[string]bool{}
	}
	if seen[ref] {
		return value
	}
	seen[ref] = true
	var current any = root
	for _, rawSegment := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		segment := strings.ReplaceAll(strings.ReplaceAll(rawSegment, "~1", "/"), "~0", "~")
		current = object(current)[segment]
		if current == nil {
			return value
		}
	}
	resolved := resolveObject(root, current, seen, depth+1)
	if resolved == nil {
		return value
	}
	if len(value) == 1 {
		return resolved
	}
	merged := make(map[string]any, len(resolved)+len(value))
	for key, item := range resolved {
		merged[key] = item
	}
	for key, item := range value {
		if key != "$ref" {
			merged[key] = item
		}
	}
	return merged
}

func openAPIReferenceDiagnostics(root map[string]any) []model.Diagnostic {
	references := map[string]struct{}{}
	nodes := 0
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 128 || nodes >= 1_000_000 {
			return
		}
		nodes++
		switch typed := value.(type) {
		case map[string]any:
			if reference := stringValue(typed["$ref"]); reference != "" {
				references[reference] = struct{}{}
			}
			for _, key := range sortedKeys(typed) {
				walk(typed[key], depth+1)
			}
		case []any:
			for _, item := range typed {
				walk(item, depth+1)
			}
		}
	}
	walk(root, 0)
	keys := make([]string, 0, len(references))
	for reference := range references {
		keys = append(keys, reference)
	}
	sort.Strings(keys)
	diagnostics := make([]model.Diagnostic, 0)
	for _, reference := range keys {
		if !strings.HasPrefix(reference, "#/") {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.ref-external", Path: safeExternalReference(reference), Message: "external $ref was not resolved", Hint: "bundle the OpenAPI document before import"})
			continue
		}
		if !openAPIPointerExists(root, reference) {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "openapi.ref-unresolved", Path: reference, Message: "internal $ref target does not exist", Hint: "repair or bundle the OpenAPI document before import"})
		}
	}
	return diagnostics
}

func safeExternalReference(reference string) string {
	base, fragment, _ := strings.Cut(reference, "#")
	parsed, err := url.Parse(base)
	if err == nil {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		base = parsed.String()
	}
	if fragment != "" {
		return base + "#" + fragment
	}
	return base
}

func openAPIPointerExists(root map[string]any, reference string) bool {
	var current any = root
	for _, rawSegment := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		segment := strings.ReplaceAll(strings.ReplaceAll(rawSegment, "~1", "/"), "~0", "~")
		container := object(current)
		if container == nil {
			return false
		}
		var exists bool
		current, exists = container[segment]
		if !exists {
			return false
		}
	}
	return true
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringList(value any) []string {
	values := list(value)
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, stringValue(item))
	}
	return result
}

func firstString(value any, fallback string) string {
	values := stringList(value)
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	return fallback
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
