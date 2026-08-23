package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/therealsylva/anyapi/internal/model"
	"github.com/therealsylva/anyapi/internal/shelllex"
)

type CurlImporter struct{}

func (CurlImporter) Name() string { return "curl" }

func (CurlImporter) Detect(source Source) int {
	trimmed := strings.TrimSpace(string(source.Data))
	if strings.HasPrefix(trimmed, "curl ") || trimmed == "curl" {
		return 100
	}
	if strings.Contains(trimmed, "\ncurl ") {
		return 90
	}
	return 0
}

type curlRequest struct {
	method      string
	getMode     bool
	rawURL      string
	headers     []string
	body        string
	forms       []string
	user        string
	cookies     []string
	diagnostics []model.Diagnostic
}

func (CurlImporter) Import(_ context.Context, source Source, options Options) (*Result, error) {
	input := strings.ReplaceAll(string(source.Data), "\\\r\n", " ")
	input = strings.ReplaceAll(input, "\\\n", " ")
	tokens, err := shelllex.Split(input)
	if err != nil {
		return nil, err
	}
	groups := splitCurlTokens(tokens)
	if len(groups) == 0 {
		return nil, fmt.Errorf("no curl command found")
	}
	document := &model.Document{APIVersion: model.APIVersion, Kind: model.KindAPI, Servers: map[string]model.Server{}, Auth: map[string]model.AuthScheme{}}
	var diagnostics []model.Diagnostic
	serverNames := map[string]string{}
	for index, group := range groups {
		request, err := parseCurl(group)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", index+1, err)
		}
		diagnostics = append(diagnostics, request.diagnostics...)
		parsed, err := url.Parse(request.rawURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("request %d has an invalid absolute URL", index+1)
		}
		if parsed.User != nil {
			request.user = "[redacted]"
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: "URL userinfo", Message: "credentials embedded in the cURL URL were removed", Hint: "provide credentials through environment variables or the OS keyring"})
		}
		if parsed.Fragment != "" {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.fragment-ignored", Path: "URL fragment", Message: "URL fragments are not sent in HTTP requests and were removed"})
		}
		if parsed.Scheme != "https" {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.insecure-url", Path: safeDiagnosticURL(parsed), Message: "request uses a non-HTTPS URL", Hint: "use HTTPS in production"})
		}
		origin := parsed.Scheme + "://" + parsed.Host
		serverName, exists := serverNames[origin]
		if !exists {
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
		if document.Metadata.Name == "" {
			document.Metadata.Name = chooseName(options, strings.Split(parsed.Hostname(), ".")[0])
			document.Metadata.Description = "CLI imported from cURL"
		}
		command, commandDiagnostics := curlCommand(document, request, parsed, serverName, index)
		diagnostics = append(diagnostics, commandDiagnostics...)
		command = uniqueCommand(document, command, &diagnostics)
		document.Commands = append(document.Commands, command)
	}
	document.Normalize()
	return &Result{Document: document, Diagnostics: diagnostics}, nil
}

func splitCurlTokens(tokens []string) [][]string {
	var groups [][]string
	var current []string
	for _, token := range tokens {
		clean := strings.TrimSuffix(token, ";")
		if clean == "curl" {
			if len(current) > 0 {
				groups = append(groups, current)
			}
			current = []string{"curl"}
			continue
		}
		if len(current) == 0 {
			continue
		}
		current = append(current, clean)
		if strings.HasSuffix(token, ";") {
			groups = append(groups, current)
			current = nil
		}
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}
	return groups
}

func parseCurl(tokens []string) (curlRequest, error) {
	request := curlRequest{method: http.MethodGet}
	next := func(index *int, option string) (string, error) {
		*index++
		if *index >= len(tokens) {
			return "", fmt.Errorf("%s requires a value", option)
		}
		return tokens[*index], nil
	}
	for index := 1; index < len(tokens); index++ {
		token := tokens[index]
		option, inline, hasInline := strings.Cut(token, "=")
		value := inline
		readValue := func() (string, error) {
			if hasInline {
				return value, nil
			}
			return next(&index, option)
		}
		switch option {
		case "-X", "--request":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.method = strings.ToUpper(value)
		case "--url":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.rawURL = value
		case "-H", "--header":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.headers = append(request.headers, value)
		case "-d", "--data", "--data-raw", "--data-ascii", "--data-urlencode", "--json":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			if request.body != "" {
				request.body += "&"
			}
			request.body += value
			if request.method == http.MethodGet && !request.getMode {
				request.method = http.MethodPost
			}
			if option == "--json" {
				request.headers = append(request.headers, "Content-Type: application/json")
			}
		case "--data-binary":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.body = value
			if request.method == http.MethodGet {
				request.method = http.MethodPost
			}
		case "-F", "--form", "--form-string":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.forms = append(request.forms, value)
			if request.method == http.MethodGet {
				request.method = http.MethodPost
			}
		case "-u", "--user":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.user = value
		case "-b", "--cookie":
			value, err := readValue()
			if err != nil {
				return request, err
			}
			request.cookies = append(request.cookies, value)
		case "-G", "--get":
			request.getMode = true
			request.method = http.MethodGet
		case "-I", "--head":
			request.method = http.MethodHead
		case "-k", "--insecure":
			request.diagnostics = append(request.diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.insecure-ignored", Message: "--insecure was intentionally not imported", Hint: "generated CLIs verify TLS certificates"})
		case "--compressed", "-s", "--silent", "-S", "--show-error", "-L", "--location", "--fail", "--fail-with-body":
			// Transport presentation options do not affect the API contract.
		default:
			if strings.HasPrefix(token, "-") {
				if curlIgnoredValueOption(option) {
					if _, err := readValue(); err != nil {
						return request, err
					}
				} else if !hasInline && index+1 < len(tokens) && !strings.HasPrefix(tokens[index+1], "-") && !absoluteHTTPURL(tokens[index+1]) && laterAbsoluteHTTPURL(tokens[index+2:]) {
					index++
				}
				request.diagnostics = append(request.diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.option-unsupported", Path: option, Message: "cURL option was not imported", Hint: "review the generated request"})
				continue
			}
			if request.rawURL == "" {
				request.rawURL = token
			} else {
				request.diagnostics = append(request.diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.argument-extra", Message: "extra cURL argument was ignored"})
			}
		}
	}
	if request.rawURL == "" {
		return request, fmt.Errorf("URL is missing")
	}
	if request.getMode && request.body != "" {
		parsed, err := url.Parse(request.rawURL)
		if err != nil {
			return request, fmt.Errorf("parse --get URL: %w", err)
		}
		data, err := url.ParseQuery(request.body)
		if err != nil {
			return request, fmt.Errorf("parse --get data: %w", err)
		}
		query := parsed.Query()
		for name, values := range data {
			for _, value := range values {
				query.Add(name, value)
			}
		}
		parsed.RawQuery = query.Encode()
		request.rawURL = parsed.String()
		request.body = ""
	}
	return request, nil
}

func curlIgnoredValueOption(option string) bool {
	switch option {
	case "-o", "--output", "-A", "--user-agent", "-e", "--referer", "-x", "--proxy", "--connect-timeout", "-m", "--max-time", "--retry", "--retry-delay", "--retry-max-time", "--cacert", "--capath", "--cert", "--key", "--resolve", "--interface", "--dns-servers", "-c", "--cookie-jar", "-T", "--upload-file":
		return true
	default:
		return false
	}
}

func absoluteHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func laterAbsoluteHTTPURL(values []string) bool {
	for _, value := range values {
		if absoluteHTTPURL(value) {
			return true
		}
	}
	return false
}

func safeDiagnosticURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	clean := *value
	clean.User = nil
	clean.RawQuery = ""
	clean.ForceQuery = false
	clean.Fragment = ""
	return clean.String()
}

var (
	doubleVariablePattern  = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}`)
	dollarVariablePattern  = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	pathPlaceholderPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_.-]*)\}`)
)

func curlCommand(document *model.Document, request curlRequest, parsed *url.URL, serverName string, index int) (model.Command, []model.Diagnostic) {
	var diagnostics []model.Diagnostic
	path := doubleVariablePattern.ReplaceAllString(parsed.EscapedPath(), `{$1}`)
	path = dollarVariablePattern.ReplaceAllStringFunc(path, func(value string) string {
		name := strings.Trim(value, "${}")
		return "{" + strings.ToLower(name) + "}"
	})
	decodedPath, err := url.PathUnescape(path)
	if err == nil {
		path = decodedPath
	}
	if path == "" {
		path = "/"
	}
	commandPath := deriveHTTPCommandPath(request.method, path)
	command := model.Command{
		ID:        strings.Join(commandPath, "."),
		Path:      commandPath,
		Summary:   fmt.Sprintf("%s %s", request.method, path),
		Operation: model.Operation{Transport: "http", Method: request.method, Path: path, Server: serverName},
		Source:    &model.SourceRecord{Format: "curl", Pointer: fmt.Sprintf("request[%d]", index)},
	}
	pathParameters := map[string]bool{}
	for _, match := range pathPlaceholderPattern.FindAllStringSubmatch(path, -1) {
		if pathParameters[match[1]] {
			continue
		}
		pathParameters[match[1]] = true
		command.Parameters = append(command.Parameters, model.Parameter{Name: match[1], Flag: model.Slug(match[1]), In: "path", Type: "string", Required: true, Positional: true})
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for _, segment := range segments {
		if _, err := strconv.ParseInt(segment, 10, 64); err == nil {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.literal-path-value", Path: path, Message: fmt.Sprintf("numeric path segment %q may be an identifier", segment), Hint: "use the interactive console to convert it into a path parameter"})
		}
	}
	query := parsed.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		values := query[key]
		if len(values) > 0 && looksSensitive(key, strings.Join(values, " ")) {
			authName := installAuthScheme(document, key, model.AuthScheme{Type: "apiKey", In: "query", Name: key, Env: model.EnvName(document.Metadata.Name, key)})
			command.Auth = appendUnique(command.Auth, authName)
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: key, Message: "sensitive query value was removed", Hint: "provide it through " + document.Auth[authName].Env + " or the OS keyring"})
			continue
		}
		parameter := model.Parameter{Name: key, Flag: model.Slug(key), In: "query", Type: "string"}
		if len(values) == 1 {
			parameter.Default = values[0]
		} else if len(values) > 1 {
			parameter.Type = "array"
			parameter.Default = values
		}
		command.Parameters = append(command.Parameters, parameter)
	}
	contentType := ""
	for _, rawHeader := range request.headers {
		name, value, ok := strings.Cut(rawHeader, ":")
		if !ok {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.header-invalid", Message: "header lacks a colon and was ignored"})
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if strings.EqualFold(name, "Content-Type") {
			contentType = strings.TrimSpace(strings.Split(value, ";")[0])
			continue
		}
		if strings.EqualFold(name, "Authorization") {
			scheme := "token"
			authType := "bearer"
			if strings.HasPrefix(strings.ToLower(value), "basic ") {
				authType = "basic"
			}
			auth := model.AuthScheme{Type: authType, In: "header", Name: "Authorization", Env: model.EnvName(document.Metadata.Name, "token")}
			if authType == "basic" {
				auth.UsernameEnv = model.EnvName(document.Metadata.Name, "username")
				auth.PasswordEnv = model.EnvName(document.Metadata.Name, "password")
			}
			scheme = installAuthScheme(document, scheme, auth)
			command.Auth = appendUnique(command.Auth, scheme)
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: "Authorization", Message: "authorization value was removed", Hint: "provide it through " + document.Auth[scheme].Env + " or the OS keyring"})
			continue
		}
		parameter := model.Parameter{Name: name, Flag: model.Slug(name), In: "header", Type: "string", Default: value, Sensitive: looksSensitive(name, value)}
		if parameter.Sensitive {
			if !strings.EqualFold(name, "Cookie") {
				authName := installAuthScheme(document, name, model.AuthScheme{Type: "apiKey", In: "header", Name: name, Env: model.EnvName(document.Metadata.Name, name)})
				command.Auth = appendUnique(command.Auth, authName)
				diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: name, Message: "sensitive header value was removed", Hint: "provide it through " + document.Auth[authName].Env + " or the OS keyring"})
				continue
			}
			parameter.Default = nil
			parameter.Required = true
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: name, Message: "sensitive header value was removed"})
		}
		command.Parameters = appendMergedParameter(command.Parameters, parameter)
	}
	if request.user != "" {
		scheme := installAuthScheme(document, "basic", model.AuthScheme{Type: "basic", UsernameEnv: model.EnvName(document.Metadata.Name, "username"), PasswordEnv: model.EnvName(document.Metadata.Name, "password")})
		command.Auth = appendUnique(command.Auth, scheme)
		diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: "--user", Message: "basic-auth credentials were removed", Hint: "provide credentials through environment variables or the OS keyring"})
	}
	if len(request.cookies) > 0 {
		command.Parameters = appendMergedParameter(command.Parameters, model.Parameter{Name: "Cookie", Flag: "cookie", In: "header", Type: "string", Required: true, Sensitive: true})
		diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: "Cookie", Message: "cookie value was removed", Hint: "provide it explicitly with --cookie"})
	}
	if len(request.forms) > 0 {
		body := &model.RequestBody{ContentType: "multipart/form-data", Required: true}
		for _, entry := range request.forms {
			name, value, ok := strings.Cut(entry, "=")
			if !ok {
				continue
			}
			field := model.Parameter{Name: name, Flag: model.Slug(name), In: "body", Type: "string", JSONPath: name, Default: value}
			if looksSensitive(name, value) {
				field.Default = nil
				field.Required = true
				field.Sensitive = true
				diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: name, Message: "sensitive form value was removed"})
			}
			if strings.HasPrefix(value, "@") {
				field.Format = "binary"
				field.Default = nil
				if !field.Sensitive {
					field.Example = filepath.Base(strings.TrimPrefix(value, "@"))
				}
			}
			body.Fields = appendMergedParameter(body.Fields, field)
		}
		command.Body = body
	} else if request.body != "" {
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
			if json.Valid([]byte(request.body)) {
				contentType = "application/json"
			}
		}
		bodyFromFile := strings.HasPrefix(request.body, "@")
		body := &model.RequestBody{ContentType: contentType, Required: true, Example: request.body}
		if contentType == "application/json" && !bodyFromFile {
			var decoded any
			if json.Unmarshal([]byte(request.body), &decoded) == nil {
				sanitized, redacted := sanitizeValue(decoded, "body")
				body.Example = sanitized
				for _, path := range redacted {
					diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: path, Message: "sensitive JSON value was removed"})
				}
				if values, ok := decoded.(map[string]any); ok {
					keys := make([]string, 0, len(values))
					for key := range values {
						keys = append(keys, key)
					}
					sortStrings(keys)
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
		if contentType == "application/x-www-form-urlencoded" && !bodyFromFile {
			if values, err := url.ParseQuery(request.body); err == nil {
				keys := make([]string, 0, len(values))
				for key := range values {
					keys = append(keys, key)
				}
				sortStrings(keys)
				for _, key := range keys {
					entries := values[key]
					field := model.Parameter{Name: key, Flag: model.Slug(key), In: "body", Type: "string", JSONPath: key}
					if len(entries) == 1 {
						field.Default = entries[0]
					} else {
						field.Type = "array"
						field.Default = append([]string(nil), entries...)
					}
					if looksSensitive(key, strings.Join(entries, " ")) {
						field.Default = nil
						field.Required = true
						field.Sensitive = true
						diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: "body." + key, Message: "sensitive form value was removed"})
					}
					body.Fields = append(body.Fields, field)
				}
			}
		}
		if !strings.Contains(contentType, "json") && looksSensitive("body", request.body) {
			body.Example = nil
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "secret.redacted", Path: "body", Message: "opaque request body appeared sensitive and was removed", Hint: "provide it at runtime with --body or --body-file"})
		}
		if bodyFromFile {
			fileName := filepath.Base(strings.TrimPrefix(request.body, "@"))
			if looksSensitive(fileName, "") {
				fileName = "[redacted-file]"
			}
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "curl.body-file", Path: fileName, Message: "body file was not read during import", Hint: "pass it to the generated command with --body-file"})
			body.Example = nil
		}
		command.Body = body
	}
	return command, diagnostics
}

func appendMergedParameter(parameters []model.Parameter, incoming model.Parameter) []model.Parameter {
	for index := range parameters {
		existing := &parameters[index]
		if existing.In != incoming.In || !strings.EqualFold(existing.Name, incoming.Name) {
			continue
		}
		existing.Required = existing.Required || incoming.Required
		existing.Sensitive = existing.Sensitive || incoming.Sensitive
		if existing.Format == "" {
			existing.Format = incoming.Format
		}
		if existing.Sensitive {
			existing.Default = nil
			existing.Example = nil
			return parameters
		}
		if existing.Example == nil {
			existing.Example = incoming.Example
		}
		values := append(interfaceValues(existing.Default), interfaceValues(incoming.Default)...)
		if len(values) == 1 {
			existing.Default = values[0]
		} else if len(values) > 1 {
			existing.Type = "array"
			existing.Default = values
		}
		return parameters
	}
	return append(parameters, incoming)
}

func interfaceValues(value any) []any {
	switch typed := value.(type) {
	case nil:
		return nil
	case []any:
		return append([]any(nil), typed...)
	case []string:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = typed[index]
		}
		return result
	default:
		return []any{typed}
	}
}

func deriveHTTPCommandPath(method, path string) []string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	resources := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" || strings.HasPrefix(segment, "{") {
			continue
		}
		if slug := model.Slug(segment); slug != "" {
			resources = append(resources, slug)
		}
	}
	resource := "request"
	if len(resources) > 0 {
		resource = resources[len(resources)-1]
	}
	hasPathParameter := pathPlaceholderPattern.MatchString(path)
	action := strings.ToLower(method)
	switch strings.ToUpper(method) {
	case http.MethodGet:
		if hasPathParameter {
			action = "get"
		} else {
			action = "list"
		}
	case http.MethodPost:
		action = "create"
	case http.MethodPut, http.MethodPatch:
		action = "update"
	case http.MethodDelete:
		action = "delete"
	}
	return []string{resource, action}
}

func inferType(value any) string {
	switch value.(type) {
	case bool:
		return "boolean"
	case float64, float32, int, int64, int32:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "string"
	}
}

func looksSensitive(name, value string) bool {
	lower := strings.ToLower(name + " " + value)
	for _, marker := range []string{"authorization", "credential", "api-key", "api_key", "apikey", "access-key", "access_key", "secret", "token", "password", "passwd", "private-key", "private_key", "cookie", "session"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{"sk_", "pk_live_", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "AKIA", "Bearer "} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	if strings.Count(trimmed, ".") == 2 && strings.HasPrefix(trimmed, "eyJ") && len(trimmed) > 40 {
		return true
	}
	return false
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
