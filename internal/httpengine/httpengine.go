package httpengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/therealsylva/anyapi/internal/apperr"
	"github.com/therealsylva/anyapi/internal/config"
	"github.com/therealsylva/anyapi/internal/credentials"
	"github.com/therealsylva/anyapi/internal/model"
)

const (
	defaultMaxResponse = int64(64 << 20)
	hardMaxResponse    = int64(512 << 20)
	maxRequestBody     = int64(128 << 20)
	maxRequestURL      = 8 << 20
	maxRetries         = 10
)

var errRequestBodyTooLarge = errors.New("request body exceeds safety limit")
var headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.max-buffer.Len() {
		return 0, errRequestBodyTooLarge
	}
	return buffer.Buffer.Write(data)
}

type Input struct {
	Values     map[string][]string
	BodyValues map[string][]string
	Body       string
	BodyFile   string
	Stdin      io.Reader
}

type Options struct {
	Server      string
	Profile     string
	Headers     []string
	Timeout     time.Duration
	InsecureTLS bool
	NoAuth      bool
	DryRun      bool
	Retries     int
	MaxResponse int64
	UserAgent   string
}

type Prepared struct {
	Method           string
	URL              string
	Headers          http.Header
	Body             []byte
	SensitiveQuery   map[string]bool
	SensitiveHeaders map[string]bool
	SensitiveBody    []string
}

func (prepared *Prepared) RedactedURL() string {
	if prepared == nil {
		return ""
	}
	parsed, err := url.Parse(prepared.URL)
	if err != nil {
		return prepared.URL
	}
	query := parsed.Query()
	for name := range query {
		if prepared.SensitiveQuery[name] || sensitiveName(name) {
			query[name] = []string{"[redacted]"}
		}
	}
	parsed.RawQuery = query.Encode()
	parsed.User = nil
	parsed.Fragment = ""
	return strings.ReplaceAll(parsed.String(), "%5Bredacted%5D", "[redacted]")
}

type Response struct {
	StatusCode int
	Status     string
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
	Prepared   *Prepared
	DryRun     bool
}

func Prepare(document *model.Document, command *model.Command, input Input, options Options) (*Prepared, error) {
	if document == nil || command == nil {
		return nil, apperr.New(apperr.ExitValidation, "validation", "document and command are required")
	}
	serverURL, profile, err := resolveServer(document, command, options)
	if err != nil {
		return nil, err
	}
	operationPath := command.Operation.Path
	headers := make(http.Header)
	sensitiveQuery := map[string]bool{}
	sensitiveHeaders := map[string]bool{}
	sensitiveBody := make([]string, 0)
	for name, value := range profile.Headers {
		headers.Set(name, value)
	}
	for _, raw := range options.Headers {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("invalid --header value %q; expected Name: Value", raw))
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !headerNamePattern.MatchString(name) || strings.ContainsAny(value, "\r\n") {
			return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("invalid --header value %q", name))
		}
		headers.Add(name, value)
	}
	query := make(url.Values)
	for _, parameter := range command.Parameters {
		if parameter.Sensitive || containsEnvironmentReference(parameter.Default) {
			switch parameter.In {
			case "query":
				sensitiveQuery[parameter.Name] = true
			case "header":
				sensitiveHeaders[strings.ToLower(parameter.Name)] = true
			}
		}
		values, present, err := parameterValues(parameter, input.Values)
		if err != nil {
			return nil, err
		}
		if !present {
			if parameter.Required {
				return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("required parameter --%s is missing", parameter.Flag))
			}
			continue
		}
		switch parameter.In {
		case "path":
			serialized, err := serializePathParameter(parameter, values)
			if err != nil {
				return nil, err
			}
			operationPath = strings.ReplaceAll(operationPath, "{"+parameter.Name+"}", serialized)
		case "query":
			if err := addQueryParameter(query, parameter, values); err != nil {
				return nil, err
			}
		case "header":
			serialized, err := serializeHeaderParameter(parameter, values)
			if err != nil {
				return nil, err
			}
			for _, value := range serialized {
				headers.Add(parameter.Name, value)
			}
		case "cookie":
			cookies, err := serializeCookieParameter(parameter, values)
			if err != nil {
				return nil, err
			}
			for _, cookieValue := range cookies {
				// #nosec G124 -- Secure, HttpOnly, and SameSite are Set-Cookie response attributes, not outbound Cookie request attributes.
				outbound := &http.Cookie{Name: cookieValue.name, Value: cookieValue.value}
				if err := outbound.Valid(); err != nil {
					return nil, apperr.New(apperr.ExitValidation, "validation", fmt.Sprintf("cookie parameter %q is invalid", parameter.Name))
				}
				headers.Add("Cookie", outbound.String())
			}
		}
	}
	if strings.Contains(operationPath, "{") {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("unresolved path placeholder remains in %s", operationPath))
	}
	fullURL := strings.TrimRight(serverURL, "/") + "/" + strings.TrimLeft(operationPath, "/")
	parsedURL, err := url.Parse(fullURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, apperr.New(apperr.ExitValidation, "validation", fmt.Sprintf("invalid request URL %q", fullURL))
	}
	mergedQuery := parsedURL.Query()
	for name, values := range query {
		mergedQuery.Del(name)
		for _, value := range values {
			mergedQuery.Add(name, value)
		}
	}
	parsedURL.RawQuery = mergedQuery.Encode()
	if len(parsedURL.String()) > maxRequestURL {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("request URL exceeds %d byte limit", maxRequestURL))
	}
	body, contentType, err := buildBody(document, command, input)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxRequestBody {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("request body exceeds %d byte limit", maxRequestBody))
	}
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}
	if options.UserAgent != "" && headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", options.UserAgent)
	}
	if command.Body != nil {
		for _, field := range command.Body.Fields {
			if field.Sensitive || containsEnvironmentReference(field.Default) {
				sensitiveBody = append(sensitiveBody, firstNonEmpty(field.JSONPath, field.Name))
			}
		}
	}
	if !options.NoAuth {
		if err := applyAuth(document, command, parsedURL, headers, sensitiveQuery, sensitiveHeaders); err != nil {
			return nil, err
		}
	}
	if len(parsedURL.String()) > maxRequestURL {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("authenticated request URL exceeds %d byte limit", maxRequestURL))
	}
	for name, values := range headers {
		if !headerNamePattern.MatchString(name) {
			return nil, apperr.New(apperr.ExitValidation, "validation", "request contains an invalid header name")
		}
		for _, value := range values {
			if !validHeaderValue(value) {
				return nil, apperr.New(apperr.ExitValidation, "validation", fmt.Sprintf("header %q contains an invalid control character", name))
			}
		}
	}
	return &Prepared{Method: command.Operation.Method, URL: parsedURL.String(), Headers: headers, Body: body, SensitiveQuery: sensitiveQuery, SensitiveHeaders: sensitiveHeaders, SensitiveBody: sensitiveBody}, nil
}

func Execute(ctx context.Context, document *model.Document, command *model.Command, input Input, options Options) (*Response, error) {
	if options.Timeout < 0 {
		return nil, apperr.New(apperr.ExitUsage, "usage", "timeout cannot be negative")
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.MaxResponse < 0 {
		return nil, apperr.New(apperr.ExitUsage, "usage", "max response cannot be negative")
	}
	if options.MaxResponse == 0 {
		options.MaxResponse = defaultMaxResponse
	}
	if options.MaxResponse > hardMaxResponse {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("max response exceeds %d byte hard limit", hardMaxResponse))
	}
	if options.Retries < 0 {
		return nil, apperr.New(apperr.ExitUsage, "usage", "retries cannot be negative")
	}
	if options.Retries > maxRetries {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("retries cannot exceed %d", maxRetries))
	}
	prepared, err := Prepare(document, command, input, options)
	if err != nil {
		return nil, err
	}
	if options.DryRun {
		return &Response{Prepared: prepared, DryRun: true}, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.InsecureTLS} // #nosec G402 -- explicit user-controlled debugging option.
	client := &http.Client{Transport: transport, Timeout: options.Timeout}
	defer transport.CloseIdleConnections()
	started := time.Now()
	var response *http.Response
	for attempt := 0; attempt <= options.Retries; attempt++ {
		request, err := http.NewRequestWithContext(ctx, prepared.Method, prepared.URL, bytes.NewReader(prepared.Body))
		if err != nil {
			return nil, apperr.Wrap(apperr.ExitTransport, "transport", "create HTTP request", err)
		}
		request.Header = prepared.Headers.Clone()
		response, err = client.Do(request)
		if err == nil && !retryStatus(response.StatusCode) {
			break
		}
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
		}
		if attempt == options.Retries || !isIdempotent(prepared.Method) {
			if err != nil {
				return nil, apperr.Wrap(apperr.ExitTransport, "transport", fmt.Sprintf("request %s %s failed", prepared.Method, prepared.RedactedURL()), err)
			}
			break
		}
		delay := time.Duration(1<<attempt) * 200 * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, apperr.Wrap(apperr.ExitTransport, "transport", "request cancelled", ctx.Err())
		case <-time.After(delay):
		}
	}
	if response == nil {
		return nil, apperr.New(apperr.ExitTransport, "transport", "HTTP client returned no response")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, options.MaxResponse+1))
	if err != nil {
		return nil, apperr.Wrap(apperr.ExitTransport, "transport", "read HTTP response", err)
	}
	if int64(len(body)) > options.MaxResponse {
		return nil, apperr.New(apperr.ExitTransport, "transport", fmt.Sprintf("response exceeds %d byte limit", options.MaxResponse))
	}
	return &Response{StatusCode: response.StatusCode, Status: response.Status, Headers: response.Header.Clone(), Body: body, Duration: time.Since(started), Prepared: prepared}, nil
}

func resolveServer(document *model.Document, command *model.Command, options Options) (string, config.Profile, error) {
	profile := config.Profile{}
	if options.Profile != "" {
		file, err := config.Load(document.Metadata.Name)
		if err != nil {
			return "", profile, apperr.Wrap(apperr.ExitValidation, "configuration", "load profile", err)
		}
		var ok bool
		profile, ok = file.Profiles[options.Profile]
		if !ok {
			return "", profile, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("profile %q is not defined", options.Profile))
		}
	}
	selection := options.Server
	if selection == "" {
		selection = profile.Server
	}
	if selection == "" {
		selection = command.Operation.Server
	}
	if selection == "" {
		selection = document.DefaultServer
	}
	serverURL := selection
	if server, ok := document.Servers[selection]; ok {
		serverURL = server.URL
		for variable, value := range server.Variables {
			serverURL = strings.ReplaceAll(serverURL, "{"+variable+"}", value)
		}
	}
	parsed, err := url.Parse(serverURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", profile, apperr.New(apperr.ExitValidation, "validation", "server selection is not a valid credential-free HTTP(S) URL or declared server name")
	}
	return strings.TrimRight(serverURL, "/"), profile, nil
}

func parameterValues(parameter model.Parameter, input map[string][]string) ([]string, bool, error) {
	values, present := input[parameter.Name]
	if !present && parameter.Flag != "" {
		values, present = input[parameter.Flag]
	}
	fromDefault := false
	if !present && parameter.Default != nil {
		values = interfaceStrings(parameter.Default)
		present = len(values) > 0
		fromDefault = present
	}
	for index, value := range values {
		if fromDefault {
			values[index] = os.ExpandEnv(value)
		}
		if err := validateScalar(parameter, values[index]); err != nil {
			return nil, false, err
		}
	}
	return values, present, nil
}

func validateScalar(parameter model.Parameter, value string) error {
	if parameter.In == "header" && strings.ContainsAny(value, "\r\n") {
		return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s cannot contain a newline", parameter.Flag))
	}
	switch parameter.Type {
	case "integer":
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s must be an integer", parameter.Flag))
		}
	case "number":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s must be a number", parameter.Flag))
		}
	case "boolean":
		if _, err := strconv.ParseBool(value); err != nil {
			return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s must be true or false", parameter.Flag))
		}
	}
	if len(parameter.Enum) > 0 {
		valid := false
		for _, option := range parameter.Enum {
			if fmt.Sprint(option) == value {
				valid = true
				break
			}
		}
		if !valid {
			return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s must be one of %v", parameter.Flag, parameter.Enum))
		}
	}
	return nil
}

func serializePathParameter(parameter model.Parameter, values []string) (string, error) {
	style := parameter.Style
	if style == "" {
		style = "simple"
	}
	if parameter.Type == "object" {
		objectValue, err := objectParameter(parameter, values)
		if err != nil {
			return "", err
		}
		keys := sortedStringKeys(objectValue)
		switch style {
		case "simple":
			parts := make([]string, 0, len(keys)*2)
			for _, key := range keys {
				if explode(parameter, false) {
					parts = append(parts, url.PathEscape(key)+"="+url.PathEscape(objectValue[key]))
				} else {
					parts = append(parts, url.PathEscape(key), url.PathEscape(objectValue[key]))
				}
			}
			return strings.Join(parts, ","), nil
		case "label":
			parts := make([]string, 0, len(keys)*2)
			for _, key := range keys {
				if explode(parameter, false) {
					parts = append(parts, url.PathEscape(key)+"="+url.PathEscape(objectValue[key]))
				} else {
					parts = append(parts, url.PathEscape(key), url.PathEscape(objectValue[key]))
				}
			}
			delimiter := ","
			if explode(parameter, false) {
				delimiter = "."
			}
			return "." + strings.Join(parts, delimiter), nil
		case "matrix":
			if explode(parameter, false) {
				var result strings.Builder
				for _, key := range keys {
					result.WriteString(";" + url.PathEscape(key) + "=" + url.PathEscape(objectValue[key]))
				}
				return result.String(), nil
			}
			parts := make([]string, 0, len(keys)*2)
			for _, key := range keys {
				parts = append(parts, url.PathEscape(key), url.PathEscape(objectValue[key]))
			}
			return ";" + url.PathEscape(parameter.Name) + "=" + strings.Join(parts, ","), nil
		}
	}
	if parameter.Type != "array" && len(values) != 1 {
		return "", apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("path parameter --%s requires one value", parameter.Flag))
	}

	escaped := make([]string, len(values))
	for index, value := range values {
		escaped[index] = url.PathEscape(value)
	}
	switch style {
	case "simple":
		return strings.Join(escaped, ","), nil
	case "label":
		delimiter := ","
		if explode(parameter, false) {
			delimiter = "."
		}
		return "." + strings.Join(escaped, delimiter), nil
	case "matrix":
		name := url.PathEscape(parameter.Name)
		if explode(parameter, false) && len(escaped) > 1 {
			return ";" + name + "=" + strings.Join(escaped, ";"+name+"="), nil
		}
		return ";" + name + "=" + strings.Join(escaped, ","), nil
	default:
		return "", unsupportedStyle(parameter, style)
	}
}

func addQueryParameter(query url.Values, parameter model.Parameter, values []string) error {
	style := parameter.Style
	if style == "" {
		style = "form"
	}
	if parameter.Type == "object" {
		objectValue, err := objectParameter(parameter, values)
		if err != nil {
			return err
		}
		keys := sortedStringKeys(objectValue)
		switch style {
		case "deepObject":
			for _, key := range keys {
				query.Add(parameter.Name+"["+key+"]", objectValue[key])
			}
			return nil
		case "form":
			if explode(parameter, true) {
				for _, key := range keys {
					query.Add(key, objectValue[key])
				}
				return nil
			}
			parts := make([]string, 0, len(keys)*2)
			for _, key := range keys {
				parts = append(parts, key, objectValue[key])
			}
			query.Add(parameter.Name, strings.Join(parts, ","))
			return nil
		default:
			return unsupportedStyle(parameter, style)
		}
	}
	switch style {
	case "form":
		if explode(parameter, true) {
			for _, value := range values {
				query.Add(parameter.Name, value)
			}
		} else {
			query.Add(parameter.Name, strings.Join(values, ","))
		}
	case "spaceDelimited":
		query.Add(parameter.Name, strings.Join(values, " "))
	case "pipeDelimited":
		query.Add(parameter.Name, strings.Join(values, "|"))
	case "deepObject":
		return unsupportedStyle(parameter, style)
	default:
		return unsupportedStyle(parameter, style)
	}
	return nil
}

func serializeHeaderParameter(parameter model.Parameter, values []string) ([]string, error) {
	style := parameter.Style
	if style == "" {
		style = "simple"
	}
	if style != "simple" {
		return nil, unsupportedStyle(parameter, style)
	}
	if parameter.Type == "object" {
		objectValue, err := objectParameter(parameter, values)
		if err != nil {
			return nil, err
		}
		keys := sortedStringKeys(objectValue)
		parts := make([]string, 0, len(keys)*2)
		for _, key := range keys {
			if explode(parameter, false) {
				parts = append(parts, key+"="+objectValue[key])
			} else {
				parts = append(parts, key, objectValue[key])
			}
		}
		return []string{strings.Join(parts, ",")}, nil
	}
	return []string{strings.Join(values, ",")}, nil
}

type cookieParameter struct {
	name  string
	value string
}

func serializeCookieParameter(parameter model.Parameter, values []string) ([]cookieParameter, error) {
	style := parameter.Style
	if style == "" {
		style = "form"
	}
	if style != "form" {
		return nil, unsupportedStyle(parameter, style)
	}
	if parameter.Type == "object" {
		objectValue, err := objectParameter(parameter, values)
		if err != nil {
			return nil, err
		}
		keys := sortedStringKeys(objectValue)
		if explode(parameter, true) {
			result := make([]cookieParameter, 0, len(keys))
			for _, key := range keys {
				result = append(result, cookieParameter{name: key, value: objectValue[key]})
			}
			return result, nil
		}
		parts := make([]string, 0, len(keys)*2)
		for _, key := range keys {
			parts = append(parts, key, objectValue[key])
		}
		return []cookieParameter{{name: parameter.Name, value: strings.Join(parts, ",")}}, nil
	}
	if explode(parameter, true) {
		result := make([]cookieParameter, 0, len(values))
		for _, value := range values {
			result = append(result, cookieParameter{name: parameter.Name, value: value})
		}
		return result, nil
	}
	return []cookieParameter{{name: parameter.Name, value: strings.Join(values, ",")}}, nil
}

func objectParameter(parameter model.Parameter, values []string) (map[string]string, error) {
	if len(values) != 1 {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s requires one JSON object", parameter.Flag))
	}
	if !json.Valid([]byte(values[0])) {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s must be a JSON object", parameter.Flag))
	}
	decoder := json.NewDecoder(strings.NewReader(values[0]))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil || decoded == nil {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s must be a JSON object", parameter.Flag))
	}
	result := make(map[string]string, len(decoded))
	for key, value := range decoded {
		switch typed := value.(type) {
		case nil:
			result[key] = ""
		case string:
			result[key] = typed
		case json.Number, bool:
			result[key] = fmt.Sprint(typed)
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("--%s contains an unsupported object value", parameter.Flag))
			}
			result[key] = string(encoded)
		}
	}
	return result, nil
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func explode(parameter model.Parameter, fallback bool) bool {
	if parameter.Explode != nil {
		return *parameter.Explode
	}
	return fallback
}

func unsupportedStyle(parameter model.Parameter, style string) error {
	return apperr.New(apperr.ExitValidation, "validation", fmt.Sprintf("parameter %q does not support %s style in %s", parameter.Name, style, parameter.In))
}

func buildBody(document *model.Document, command *model.Command, input Input) ([]byte, string, error) {
	if command.Body == nil {
		if input.Body != "" || input.BodyFile != "" {
			return nil, "", apperr.New(apperr.ExitUsage, "usage", "this command does not define a request body")
		}
		return nil, "", nil
	}
	if input.Body != "" && input.BodyFile != "" {
		return nil, "", apperr.New(apperr.ExitUsage, "usage", "--body and --body-file are mutually exclusive")
	}
	if input.BodyFile != "" {
		data, err := readBodyFile(input.BodyFile, input.Stdin)
		if err != nil {
			return nil, "", err
		}
		return data, command.Body.ContentType, nil
	}
	if input.Body != "" {
		return []byte(input.Body), command.Body.ContentType, nil
	}
	switch {
	case strings.HasPrefix(command.Body.ContentType, "multipart/form-data"):
		return multipartBody(command.Body, input.BodyValues)
	case command.Body.ContentType == "application/x-www-form-urlencoded":
		values := make(url.Values)
		for _, field := range command.Body.Fields {
			fieldValues, present, err := parameterValues(field, input.BodyValues)
			if err != nil {
				return nil, "", err
			}
			if !present && field.Required {
				return nil, "", apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("required body field --%s is missing", field.Flag))
			}
			for _, value := range fieldValues {
				values.Add(field.Name, value)
			}
		}
		if len(values) == 0 && command.Body.Required {
			if document.Import != nil && (document.Import.Format == "curl" || document.Import.Format == "postman") {
				if example, ok := command.Body.Example.(string); ok && example != "" {
					return []byte(example), command.Body.ContentType, nil
				}
			}
			return nil, "", apperr.New(apperr.ExitUsage, "usage", "request body is required")
		}
		return []byte(values.Encode()), command.Body.ContentType, nil
	case strings.Contains(command.Body.ContentType, "json"):
		payload := importedExampleObject(document, command.Body)
		provided := false
		for _, field := range command.Body.Fields {
			fieldValues, present, err := parameterValues(field, input.BodyValues)
			if err != nil {
				return nil, "", err
			}
			if !present {
				if field.Required {
					return nil, "", apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("required body field --%s is missing", field.Flag))
				}
				continue
			}
			provided = true
			setNested(payload, firstNonEmpty(field.JSONPath, field.Name), typedValue(field, fieldValues))
		}
		if !provided && document.Import != nil && (document.Import.Format == "curl" || document.Import.Format == "postman") && command.Body.Example != nil {
			data, err := json.Marshal(command.Body.Example)
			return data, command.Body.ContentType, err
		}
		if !provided && command.Body.Required && len(command.Body.Fields) == 0 {
			return nil, "", apperr.New(apperr.ExitUsage, "usage", "request body is required; use --body or --body-file")
		}
		if !provided && !command.Body.Required {
			return nil, "", nil
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, "", apperr.Wrap(apperr.ExitValidation, "validation", "encode JSON body", err)
		}
		return data, command.Body.ContentType, nil
	default:
		if document.Import != nil && (document.Import.Format == "curl" || document.Import.Format == "postman") {
			if value, ok := command.Body.Example.(string); ok {
				return []byte(value), command.Body.ContentType, nil
			}
		}
		if command.Body.Required {
			return nil, "", apperr.New(apperr.ExitUsage, "usage", "request body is required; use --body or --body-file")
		}
		return nil, "", nil
	}
}

func multipartBody(body *model.RequestBody, values map[string][]string) ([]byte, string, error) {
	buffer := limitedBuffer{max: int(maxRequestBody)}
	writer := multipart.NewWriter(&buffer)
	provided := false
	for _, field := range body.Fields {
		fieldValues, present, err := parameterValues(field, values)
		if err != nil {
			_ = writer.Close()
			return nil, "", err
		}
		if !present {
			if field.Required {
				_ = writer.Close()
				return nil, "", apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("required body field --%s is missing", field.Flag))
			}
			continue
		}
		provided = true
		for _, value := range fieldValues {
			if field.Format != "binary" {
				if err := writer.WriteField(field.Name, value); err != nil {
					_ = writer.Close()
					return nil, "", multipartError(err)
				}
				continue
			}
			// #nosec G304 -- upload paths are explicit CLI inputs and intentionally unrestricted local file reads.
			file, err := os.Open(value)
			if err != nil {
				_ = writer.Close()
				return nil, "", apperr.Wrap(apperr.ExitUsage, "usage", "open upload file", err)
			}
			part, err := writer.CreateFormFile(field.Name, filepath.Base(value))
			if err == nil {
				_, err = io.Copy(part, io.LimitReader(file, maxRequestBody+1))
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				_ = writer.Close()
				return nil, "", multipartError(err)
			}
		}
	}
	if !provided && body.Required {
		_ = writer.Close()
		return nil, "", apperr.New(apperr.ExitUsage, "usage", "request body is required")
	}
	if err := writer.Close(); err != nil {
		return nil, "", multipartError(err)
	}
	return buffer.Bytes(), writer.FormDataContentType(), nil
}

func multipartError(err error) error {
	if errors.Is(err, errRequestBodyTooLarge) {
		return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("request body exceeds %d byte limit", maxRequestBody))
	}
	return apperr.Wrap(apperr.ExitTransport, "transport", "encode multipart body", err)
}

func readBodyFile(path string, stdin io.Reader) ([]byte, error) {
	var reader io.Reader
	var file *os.File
	if path == "-" {
		if stdin == nil {
			return nil, apperr.New(apperr.ExitUsage, "usage", "stdin is unavailable")
		}
		reader = stdin
	} else {
		// #nosec G304 -- body-file is an explicit CLI input and intentionally supports arbitrary local files.
		opened, err := os.Open(path)
		if err != nil {
			return nil, apperr.Wrap(apperr.ExitUsage, "usage", "open body file", err)
		}
		file = opened
		defer file.Close()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxRequestBody+1))
	if err != nil {
		return nil, apperr.Wrap(apperr.ExitTransport, "transport", "read body", err)
	}
	if int64(len(data)) > maxRequestBody {
		return nil, apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("request body exceeds %d byte limit", maxRequestBody))
	}
	return data, nil
}

func applyAuth(document *model.Document, command *model.Command, requestURL *url.URL, headers http.Header, sensitiveQuery, sensitiveHeaders map[string]bool) error {
	for _, name := range command.Auth {
		scheme, ok := document.Auth[name]
		if !ok {
			return apperr.New(apperr.ExitValidation, "validation", fmt.Sprintf("authentication scheme %q is undefined", name))
		}
		switch strings.ToLower(scheme.Type) {
		case "bearer", "oauth2", "openidconnect":
			value, err := credentials.Resolve(document.Metadata.Name, name, scheme)
			if err != nil {
				return apperr.Wrap(apperr.ExitAuth, "authentication", err.Error(), err)
			}
			headers.Set("Authorization", "Bearer "+value)
			sensitiveHeaders["authorization"] = true
		case "apikey":
			value, err := credentials.Resolve(document.Metadata.Name, name, scheme)
			if err != nil {
				return apperr.Wrap(apperr.ExitAuth, "authentication", err.Error(), err)
			}
			switch strings.ToLower(scheme.In) {
			case "query":
				query := requestURL.Query()
				query.Set(scheme.Name, value)
				requestURL.RawQuery = query.Encode()
				sensitiveQuery[scheme.Name] = true
			case "cookie":
				// #nosec G124 -- Secure, HttpOnly, and SameSite are Set-Cookie response attributes, not outbound Cookie request attributes.
				outbound := &http.Cookie{Name: scheme.Name, Value: value}
				if err := outbound.Valid(); err != nil {
					return apperr.New(apperr.ExitAuth, "authentication", fmt.Sprintf("credential for %q is not a valid cookie value", name))
				}
				headers.Add("Cookie", outbound.String())
				sensitiveHeaders["cookie"] = true
			default:
				headers.Set(scheme.Name, value)
				sensitiveHeaders[strings.ToLower(scheme.Name)] = true
			}
		case "basic":
			username, password, err := credentials.ResolveBasic(document.Metadata.Name, name, scheme)
			if err != nil {
				return apperr.Wrap(apperr.ExitAuth, "authentication", err.Error(), err)
			}
			headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
			sensitiveHeaders["authorization"] = true
		case "":
			continue
		default:
			return apperr.New(apperr.ExitAuth, "authentication", fmt.Sprintf("authentication type %q is not executable in this release", scheme.Type))
		}
	}
	return nil
}

func importedExampleObject(document *model.Document, body *model.RequestBody) map[string]any {
	result := map[string]any{}
	if document == nil || document.Import == nil || body == nil || (document.Import.Format != "curl" && document.Import.Format != "postman") {
		return result
	}
	value, ok := body.Example.(map[string]any)
	if !ok {
		return result
	}
	data, err := json.Marshal(value)
	if err != nil || json.Unmarshal(data, &result) != nil {
		return map[string]any{}
	}
	return result
}

func validHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}
	return true
}

func sensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"authorization", "credential", "api-key", "api_key", "apikey", "access-key", "access_key", "secret", "token", "password", "passwd", "private-key", "private_key", "cookie", "session"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func interfaceStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, fmt.Sprint(item))
		}
		return values
	case nil:
		return nil
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func containsEnvironmentReference(value any) bool {
	for _, text := range interfaceStrings(value) {
		if strings.Contains(text, "$") {
			return true
		}
	}
	return false
}

func typedValue(parameter model.Parameter, values []string) any {
	if parameter.Type == "array" || len(values) > 1 {
		result := make([]any, 0, len(values))
		for _, value := range values {
			copy := parameter
			copy.Type = "string"
			result = append(result, typedValue(copy, []string{value}))
		}
		return result
	}
	if len(values) == 0 {
		return nil
	}
	switch parameter.Type {
	case "integer":
		value, _ := strconv.ParseInt(values[0], 10, 64)
		return value
	case "number":
		value, _ := strconv.ParseFloat(values[0], 64)
		return value
	case "boolean":
		value, _ := strconv.ParseBool(values[0])
		return value
	case "object":
		var value any
		if json.Unmarshal([]byte(values[0]), &value) == nil {
			return value
		}
	}
	return values[0]
}

func setNested(target map[string]any, path string, value any) {
	parts := strings.Split(strings.Trim(path, "."), ".")
	current := target
	for index, part := range parts {
		if index == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
}

func retryStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
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
