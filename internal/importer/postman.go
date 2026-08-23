package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/therealsylva/anyapi/internal/model"
)

type PostmanImporter struct{}

func (PostmanImporter) Name() string { return "postman" }

func (PostmanImporter) Detect(source Source) int {
	root, err := decodeGeneric(source.Data)
	if err != nil {
		return 0
	}
	info := object(root["info"])
	schema := strings.ToLower(stringValue(info["schema"]))
	if strings.Contains(schema, "postman") || info["_postman_id"] != nil {
		return 100
	}
	if list(root["item"]) != nil && info["name"] != nil {
		return 70
	}
	return 0
}

func (PostmanImporter) Import(_ context.Context, source Source, options Options) (*Result, error) {
	root, err := decodeGeneric(source.Data)
	if err != nil {
		return nil, err
	}
	info := object(root["info"])
	name := chooseName(options, stringValue(info["name"]))
	document := &model.Document{
		APIVersion: model.APIVersion,
		Kind:       model.KindAPI,
		Metadata: model.Metadata{
			Name:        name,
			Version:     "1.0.0",
			Description: stringValue(info["description"]),
		},
		Servers: map[string]model.Server{},
		Auth:    map[string]model.AuthScheme{},
	}
	variables := postmanVariables(root["variable"])
	var diagnostics []model.Diagnostic
	if len(list(root["event"])) > 0 {
		diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.scripts-skipped", Path: "event", Message: "collection scripts were not imported or executed", Hint: "replace required behavior with explicit CLI parameters"})
	}
	serverNames := map[string]string{}
	walkPostmanItems(document, list(root["item"]), nil, variables, object(root["auth"]), serverNames, &diagnostics, 0)
	if len(document.Commands) == 0 {
		return nil, fmt.Errorf("collection contains no supported requests")
	}
	if len(document.Servers) == 0 {
		document.Servers["production"] = model.Server{URL: "https://api.example.invalid", Description: "Replace with the API server URL"}
		document.DefaultServer = "production"
		diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.server-missing", Path: "variable", Message: "collection has no resolvable absolute request URL", Hint: "set the production server before use"})
	}
	document.Normalize()
	return &Result{Document: document, Diagnostics: diagnostics}, nil
}

func walkPostmanItems(document *model.Document, items []any, folders []string, variables map[string]string, inheritedAuth map[string]any, serverNames map[string]string, diagnostics *[]model.Diagnostic, depth int) {
	if depth > 128 {
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.folder-depth", Path: strings.Join(folders, "."), Message: "nested folders beyond depth 128 were skipped", Hint: "flatten the collection before import"})
		return
	}
	for _, rawItem := range items {
		item := object(rawItem)
		if item == nil {
			continue
		}
		name := stringValue(item["name"])
		if children := list(item["item"]); children != nil {
			folder := model.Slug(name)
			nextFolders := append([]string(nil), folders...)
			if folder != "" {
				nextFolders = append(nextFolders, folder)
			}
			auth := inheritedAuth
			if candidate := object(item["auth"]); candidate != nil {
				auth = candidate
			}
			if len(list(item["event"])) > 0 {
				*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.scripts-skipped", Path: strings.Join(nextFolders, "."), Message: "folder scripts were not imported or executed"})
			}
			walkPostmanItems(document, children, nextFolders, variables, auth, serverNames, diagnostics, depth+1)
			continue
		}
		request := item["request"]
		requestObject := object(request)
		if requestObject == nil {
			if rawURL, ok := request.(string); ok {
				requestObject = map[string]any{"method": "GET", "url": rawURL}
			} else {
				continue
			}
		}
		command, ok := postmanCommand(document, requestObject, name, folders, variables, inheritedAuth, serverNames, diagnostics)
		if !ok {
			continue
		}
		if len(list(item["event"])) > 0 {
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.scripts-skipped", Path: command.ID, Message: "request scripts were not imported or executed"})
		}
		command = uniqueCommand(document, command, diagnostics)
		document.Commands = append(document.Commands, command)
	}
}

func postmanCommand(document *model.Document, request map[string]any, itemName string, folders []string, variables map[string]string, inheritedAuth map[string]any, serverNames map[string]string, diagnostics *[]model.Diagnostic) (model.Command, bool) {
	method := strings.ToUpper(stringValue(request["method"]))
	if method == "" {
		method = "GET"
	}
	rawURL, queryItems, pathVariables := postmanURL(request["url"])
	if rawURL == "" {
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.url-missing", Path: itemName, Message: "request URL is missing and was skipped"})
		return model.Command{}, false
	}
	rawURL = replacePostmanBaseVariables(rawURL, variables)
	rawURL = strings.ReplaceAll(rawURL, "://", "__SCHEME__")
	rawURL = doubleVariablePattern.ReplaceAllString(rawURL, `{$1}`)
	rawURL = strings.ReplaceAll(rawURL, "__SCHEME__", "://")
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.url-unresolved", Path: itemName, Message: "request URL is not an absolute URL and was skipped", Hint: "define collection base URL variables"})
		return model.Command{}, false
	}
	origin := parsed.Scheme + "://" + parsed.Host
	serverName := serverNames[origin]
	if serverName == "" {
		serverName = "production"
		if len(serverNames) > 0 {
			serverName = fmt.Sprintf("server-%d", len(serverNames)+1)
		}
		serverNames[origin] = serverName
		document.Servers[serverName] = model.Server{URL: origin}
		if document.DefaultServer == "" {
			document.DefaultServer = serverName
		}
	}
	path := parsed.Path
	path = regexpColonParameter(path)
	if path == "" {
		path = "/"
	}
	commandPath := make([]string, 0, len(folders)+1)
	for _, folder := range folders {
		if folder != "" {
			commandPath = append(commandPath, safeRoot(folder))
		}
	}
	if itemSlug := model.Slug(itemName); itemSlug != "" {
		commandPath = append(commandPath, itemSlug)
	}
	if len(commandPath) == 0 {
		commandPath = deriveHTTPCommandPath(method, path)
	}
	command := model.Command{
		ID:          strings.Join(commandPath, "."),
		Path:        commandPath,
		Summary:     itemName,
		Description: stringValue(request["description"]),
		Operation:   model.Operation{Transport: "http", Method: method, Path: path, Server: serverName},
		Source:      &model.SourceRecord{Format: "postman", Pointer: strings.Join(commandPath, "/")},
	}
	if parsed.User != nil {
		authName := installAuthScheme(document, "basic", model.AuthScheme{Type: "basic", UsernameEnv: model.EnvName(document.Metadata.Name, "username"), PasswordEnv: model.EnvName(document.Metadata.Name, "password")})
		command.Auth = appendUnique(command.Auth, authName)
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: command.ID + ".URL userinfo", Message: "credentials embedded in the Postman URL were removed", Hint: "provide credentials through environment variables or the OS keyring"})
	}
	if parsed.Fragment != "" {
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.fragment-ignored", Path: command.ID, Message: "URL fragments are not sent in HTTP requests and were removed"})
	}
	parameterSet := map[string]bool{}
	for _, match := range pathPlaceholderPattern.FindAllStringSubmatch(path, -1) {
		key := "path:" + match[1]
		if parameterSet[key] {
			continue
		}
		parameterSet[key] = true
		parameter := model.Parameter{Name: match[1], Flag: model.Slug(match[1]), In: "path", Type: "string", Required: true, Positional: true}
		if value := pathVariables[match[1]]; value != "" {
			parameter.Example = value
		}
		command.Parameters = append(command.Parameters, parameter)
	}
	if len(queryItems) == 0 {
		for key, values := range parsed.Query() {
			for _, value := range values {
				queryItems = append(queryItems, postmanQuery{Key: key, Value: value})
			}
		}
	}
	sort.SliceStable(queryItems, func(i, j int) bool { return queryItems[i].Key < queryItems[j].Key })
	for _, query := range queryItems {
		if query.Disabled || query.Key == "" {
			continue
		}
		value := replacePostmanValue(query.Value, variables)
		if looksSensitive(query.Key, value) {
			authName := model.Slug(query.Key)
			document.Auth[authName] = model.AuthScheme{Type: "apiKey", In: "query", Name: query.Key, Env: model.EnvName(document.Metadata.Name, query.Key)}
			command.Auth = appendUnique(command.Auth, authName)
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: command.ID + "." + query.Key, Message: "sensitive query value was removed"})
			continue
		}
		parameter := model.Parameter{Name: query.Key, Flag: model.Slug(query.Key), In: "query", Type: "string", Description: query.Description, Default: value}
		if match := pathPlaceholderPattern.FindStringSubmatch(value); len(match) == 2 && match[0] == value {
			parameter.Default = nil
			parameter.Example = variables[match[1]]
		}
		command.Parameters = appendMergedParameter(command.Parameters, parameter)
	}
	contentType := ""
	for _, rawHeader := range list(request["header"]) {
		header := object(rawHeader)
		if header == nil || boolValue(header["disabled"]) {
			continue
		}
		name := stringValue(header["key"])
		value := replacePostmanValue(stringValue(header["value"]), variables)
		if strings.EqualFold(name, "Content-Type") {
			contentType = strings.TrimSpace(strings.Split(value, ";")[0])
			continue
		}
		if strings.EqualFold(name, "Authorization") {
			installHeaderAuth(document, &command, value, diagnostics)
			continue
		}
		parameter := model.Parameter{Name: name, Flag: model.Slug(name), In: "header", Type: "string", Description: stringValue(header["description"]), Default: value, Sensitive: looksSensitive(name, value)}
		if parameter.Sensitive {
			parameter.Default = nil
			parameter.Required = true
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: command.ID + "." + name, Message: "sensitive Postman header value was removed"})
		}
		command.Parameters = appendMergedParameter(command.Parameters, parameter)
	}
	auth := inheritedAuth
	if candidate := object(request["auth"]); candidate != nil {
		auth = candidate
	}
	if auth != nil {
		applyPostmanAuth(document, &command, auth, diagnostics)
	}
	command.Body = postmanBody(request["body"], contentType, variables, diagnostics, command.ID)
	return command, true
}

type postmanQuery struct {
	Key         string
	Value       string
	Description string
	Disabled    bool
}

func postmanURL(raw any) (string, []postmanQuery, map[string]string) {
	if value, ok := raw.(string); ok {
		return value, nil, nil
	}
	objectValue := object(raw)
	if objectValue == nil {
		return "", nil, nil
	}
	rawURL := stringValue(objectValue["raw"])
	if rawURL == "" {
		protocol := stringValue(objectValue["protocol"])
		host := joinPostmanParts(objectValue["host"], ".")
		path := joinPostmanParts(objectValue["path"], "/")
		rawURL = protocol + "://" + host + "/" + path
	}
	queries := []postmanQuery{}
	for _, rawQuery := range list(objectValue["query"]) {
		query := object(rawQuery)
		queries = append(queries, postmanQuery{Key: stringValue(query["key"]), Value: stringValue(query["value"]), Description: stringValue(query["description"]), Disabled: boolValue(query["disabled"])})
	}
	variables := map[string]string{}
	for _, rawVariable := range list(objectValue["variable"]) {
		variable := object(rawVariable)
		variables[stringValue(variable["key"])] = stringValue(variable["value"])
	}
	return rawURL, queries, variables
}

func postmanVariables(raw any) map[string]string {
	result := map[string]string{}
	for _, rawVariable := range list(raw) {
		variable := object(rawVariable)
		name := stringValue(variable["key"])
		if name == "" {
			name = stringValue(variable["id"])
		}
		if name != "" {
			value := stringValue(variable["value"])
			if strings.EqualFold(stringValue(variable["type"]), "secret") || looksSensitive(name, value) {
				value = "${" + model.EnvName(name) + "}"
			}
			result[name] = value
		}
	}
	if mapped := object(raw); mapped != nil {
		for key, value := range mapped {
			text := stringValue(value)
			if looksSensitive(key, text) {
				text = "${" + model.EnvName(key) + "}"
			}
			result[key] = text
		}
	}
	return result
}

func replacePostmanBaseVariables(raw string, variables map[string]string) string {
	return doubleVariablePattern.ReplaceAllStringFunc(raw, func(match string) string {
		parts := doubleVariablePattern.FindStringSubmatch(match)
		name := parts[1]
		value := variables[name]
		lower := strings.ToLower(name)
		if value != "" && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.Contains(lower, "base") || strings.Contains(lower, "host") || strings.Contains(lower, "url") || strings.Contains(lower, "domain") || strings.Contains(lower, "scheme") || strings.Contains(lower, "protocol")) {
			return value
		}
		if strings.Contains(lower, "base") || strings.Contains(lower, "host") || strings.Contains(lower, "url") {
			return "https://api.example.invalid"
		}
		return match
	})
}

func replacePostmanValue(raw string, variables map[string]string) string {
	return doubleVariablePattern.ReplaceAllStringFunc(raw, func(match string) string {
		parts := doubleVariablePattern.FindStringSubmatch(match)
		if value := variables[parts[1]]; value != "" {
			return value
		}
		return "${" + model.EnvName(parts[1]) + "}"
	})
}

func regexpColonParameter(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if strings.HasPrefix(segment, ":") && len(segment) > 1 {
			segments[index] = "{" + strings.TrimPrefix(segment, ":") + "}"
		}
	}
	return strings.Join(segments, "/")
}

func joinPostmanParts(value any, separator string) string {
	if text, ok := value.(string); ok {
		return text
	}
	parts := stringList(value)
	return strings.Join(parts, separator)
}

func installHeaderAuth(document *model.Document, command *model.Command, value string, diagnostics *[]model.Diagnostic) {
	typeName := "bearer"
	if strings.HasPrefix(strings.ToLower(value), "basic ") {
		typeName = "basic"
	}
	auth := model.AuthScheme{Type: typeName, Env: model.EnvName(document.Metadata.Name, "token")}
	if typeName == "basic" {
		auth.UsernameEnv = model.EnvName(document.Metadata.Name, "username")
		auth.PasswordEnv = model.EnvName(document.Metadata.Name, "password")
	}
	name := installAuthScheme(document, "token", auth)
	command.Auth = appendUnique(command.Auth, name)
	*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: command.ID + ".Authorization", Message: "authorization header was removed", Hint: "provide credentials through environment variables or the OS keyring"})
}

func applyPostmanAuth(document *model.Document, command *model.Command, raw map[string]any, diagnostics *[]model.Diagnostic) {
	typeName := strings.ToLower(stringValue(raw["type"]))
	if typeName == "" || typeName == "noauth" {
		return
	}
	values := map[string]string{}
	for _, rawValue := range list(raw[typeName]) {
		value := object(rawValue)
		values[stringValue(value["key"])] = stringValue(value["value"])
	}
	name := model.Slug(typeName)
	auth := model.AuthScheme{Env: model.EnvName(document.Metadata.Name, name)}
	switch typeName {
	case "bearer", "oauth2":
		auth.Type = typeName
	case "apikey":
		auth.Type = "apiKey"
		auth.Name = values["key"]
		auth.In = values["in"]
		if auth.In == "" {
			auth.In = "header"
		}
	case "basic":
		auth.Type = "basic"
		auth.UsernameEnv = model.EnvName(document.Metadata.Name, "username")
		auth.PasswordEnv = model.EnvName(document.Metadata.Name, "password")
	case "digest", "hawk", "awsv4", "ntlm":
		auth.Type = typeName
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.auth-advanced", Path: command.ID, Message: fmt.Sprintf("Postman authentication type %q requires manual review", typeName)})
	default:
		auth.Type = typeName
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.auth-unknown", Path: command.ID, Message: fmt.Sprintf("unknown Postman authentication type %q", typeName)})
	}
	name = installAuthScheme(document, name, auth)
	command.Auth = appendUnique(command.Auth, name)
	*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: command.ID + ".auth", Message: "Postman authentication values were removed", Hint: "provide credentials through environment variables or the OS keyring"})
}

func postmanBody(raw any, contentType string, variables map[string]string, diagnostics *[]model.Diagnostic, commandID string) *model.RequestBody {
	bodyObject := object(raw)
	if bodyObject == nil || boolValue(bodyObject["disabled"]) {
		return nil
	}
	mode := strings.ToLower(stringValue(bodyObject["mode"]))
	switch mode {
	case "raw":
		value := replacePostmanValue(stringValue(bodyObject["raw"]), variables)
		if contentType == "" {
			language := strings.ToLower(stringValue(object(object(bodyObject["options"])["raw"])["language"]))
			if language == "json" || json.Valid([]byte(value)) {
				contentType = "application/json"
			} else {
				contentType = "text/plain"
			}
		}
		body := &model.RequestBody{ContentType: contentType, Required: true, Example: value}
		if strings.Contains(contentType, "json") {
			var decoded any
			if json.Unmarshal([]byte(value), &decoded) == nil {
				sanitized, redacted := sanitizeValue(decoded, "body")
				body.Example = sanitized
				for _, path := range redacted {
					*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: commandID + "." + path, Message: "sensitive JSON value was removed"})
				}
				if values, ok := decoded.(map[string]any); ok {
					keys := make([]string, 0, len(values))
					for key := range values {
						keys = append(keys, key)
					}
					sort.Strings(keys)
					for _, key := range keys {
						field := model.Parameter{Name: key, Flag: model.Slug(key), In: "body", Type: inferType(values[key]), JSONPath: key, Example: values[key]}
						if looksSensitive(key, stringValue(values[key])) {
							field.Example = nil
							field.Required = true
							field.Sensitive = true
						}
						body.Fields = append(body.Fields, field)
					}
				}
			}
		}
		return body
	case "formdata", "urlencoded":
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
			if mode == "formdata" {
				contentType = "multipart/form-data"
			}
		}
		body := &model.RequestBody{ContentType: contentType, Required: true}
		for _, rawField := range list(bodyObject[mode]) {
			fieldObject := object(rawField)
			if boolValue(fieldObject["disabled"]) {
				continue
			}
			name := stringValue(fieldObject["key"])
			field := model.Parameter{Name: name, Flag: model.Slug(name), In: "body", Type: "string", JSONPath: name, Description: stringValue(fieldObject["description"]), Default: replacePostmanValue(stringValue(fieldObject["value"]), variables)}
			if looksSensitive(name, stringValue(field.Default)) {
				field.Default = nil
				field.Required = true
				field.Sensitive = true
				*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: commandID + ".body." + name, Message: "sensitive form value was removed"})
			}
			if stringValue(fieldObject["type"]) == "file" {
				field.Format = "binary"
				field.Default = nil
				field.Example = nil
			}
			body.Fields = appendMergedParameter(body.Fields, field)
		}
		return body
	case "graphql":
		graphql := object(bodyObject["graphql"])
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.graphql-http", Path: commandID, Message: "GraphQL request was imported as a raw HTTP JSON body"})
		variablesValue := any(stringValue(graphql["variables"]))
		var decoded any
		if json.Unmarshal([]byte(stringValue(graphql["variables"])), &decoded) == nil {
			var redacted []string
			variablesValue, redacted = sanitizeValue(decoded, "body.variables")
			for _, path := range redacted {
				*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: commandID + "." + path, Message: "sensitive GraphQL variable was removed"})
			}
		}
		return &model.RequestBody{ContentType: "application/json", Example: map[string]any{"query": stringValue(graphql["query"]), "variables": variablesValue}}
	case "file":
		return &model.RequestBody{ContentType: firstNonEmpty(contentType, "application/octet-stream"), Description: "Binary request body"}
	default:
		if mode != "" {
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "postman.body-unsupported", Path: commandID, Message: fmt.Sprintf("body mode %q was not imported", mode)})
		}
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
