package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/therealsylva/anyapi/internal/model"
	"go.yaml.in/yaml/v3"
)

const MaxSourceSize = 50 << 20

type Source struct {
	Location string
	Data     []byte
	BaseDir  string
	URL      *url.URL
}

type Options struct {
	Format    string
	Name      string
	AllowHTTP bool
}

type Result struct {
	Document    *model.Document
	Diagnostics []model.Diagnostic
}

type Importer interface {
	Name() string
	Detect(Source) int
	Import(context.Context, Source, Options) (*Result, error)
}

type Registry struct {
	importers []Importer
}

func NewRegistry() *Registry {
	return &Registry{importers: []Importer{CurlImporter{}, OpenAPIImporter{}, PostmanImporter{}}}
}

func (registry *Registry) Import(ctx context.Context, source Source, options Options) (*Result, error) {
	format := strings.ToLower(strings.TrimSpace(options.Format))
	var selected Importer
	best := 0
	for _, candidate := range registry.importers {
		if format != "" && format != "auto" {
			if candidate.Name() == format {
				selected = candidate
				break
			}
			continue
		}
		if score := candidate.Detect(source); score > best {
			selected = candidate
			best = score
		}
	}
	if selected == nil {
		if format != "" && format != "auto" {
			return nil, fmt.Errorf("unsupported import format %q", format)
		}
		return nil, errors.New("could not detect source format; use --format curl, openapi, or postman")
	}
	result, err := selected.Import(ctx, source, options)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", selected.Name(), err)
	}
	if result == nil || result.Document == nil {
		return nil, fmt.Errorf("importer %s returned no document", selected.Name())
	}
	result.Document.Normalize()
	for index := range result.Diagnostics {
		result.Diagnostics[index] = model.CleanDiagnostic(result.Diagnostics[index])
	}
	digest := sha256.Sum256(source.Data)
	result.Document.Import = &model.ImportMetadata{
		Format:      selected.Name(),
		Source:      source.Location,
		Fingerprint: "sha256:" + hex.EncodeToString(digest[:]),
		Diagnostics: append([]model.Diagnostic(nil), result.Diagnostics...),
	}
	if result.Document.Metadata.Source == "" {
		result.Document.Metadata.Source = source.Location
	}
	return result, nil
}

func LoadSource(ctx context.Context, location string, stdin io.Reader, allowHTTP bool) (Source, error) {
	if location == "-" {
		data, err := readLimited(stdin, MaxSourceSize)
		if err != nil {
			return Source{}, fmt.Errorf("read stdin: %w", err)
		}
		return Source{Location: "stdin", Data: data}, nil
	}
	parsed, err := url.Parse(location)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
			return Source{}, fmt.Errorf("remote source must use HTTPS; pass --allow-http to permit HTTP")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return Source{}, fmt.Errorf("create source request: %w", err)
		}
		safeLocation := sanitizedRemoteLocation(parsed)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				if request.URL.Scheme != "https" && !(allowHTTP && request.URL.Scheme == "http") {
					return errors.New("redirected to an unencrypted URL")
				}
				return nil
			},
		}
		defer transport.CloseIdleConnections()
		response, err := client.Do(request)
		if err != nil {
			if urlError, ok := err.(*url.Error); ok {
				err = urlError.Err
			}
			return Source{}, fmt.Errorf("download source %s: %w", safeLocation, err)
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return Source{}, fmt.Errorf("download source: HTTP %s", response.Status)
		}
		data, err := readLimited(response.Body, MaxSourceSize)
		if err != nil {
			return Source{}, fmt.Errorf("download source: %w", err)
		}
		finalURL := *response.Request.URL
		finalURL.User = nil
		finalURL.RawQuery = ""
		finalURL.ForceQuery = false
		finalURL.Fragment = ""
		return Source{Location: safeLocation, Data: data, URL: &finalURL}, nil
	}
	// #nosec G304 -- location is the explicit local source path supplied by the user.
	file, err := os.Open(location)
	if err != nil {
		return Source{}, fmt.Errorf("open %s: %w", location, err)
	}
	defer file.Close()
	data, err := readLimited(file, MaxSourceSize)
	if err != nil {
		return Source{}, fmt.Errorf("read %s: %w", location, err)
	}
	absolute, _ := filepath.Abs(location)
	return Source{Location: location, Data: data, BaseDir: filepath.Dir(absolute)}, nil
}

func sanitizedRemoteLocation(value *url.URL) string {
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

func InlineSource(value string) Source {
	return Source{Location: "inline", Data: []byte(value)}
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds %d byte limit", limit)
	}
	return data, nil
}

func decodeGeneric(data []byte) (map[string]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("source is not an object")
	}
	return value, nil
}

func object(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return nil
}

func list(value any) []any {
	if result, ok := value.([]any); ok {
		return result
	}
	return nil
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func chooseName(options Options, fallback string) string {
	if strings.TrimSpace(options.Name) != "" {
		return model.Slug(options.Name)
	}
	if slug := model.Slug(fallback); slug != "" {
		return slug
	}
	return "api"
}

func uniqueCommand(document *model.Document, command model.Command, diagnostics *[]model.Diagnostic) model.Command {
	if len(command.Path) > 0 {
		switch command.Path[0] {
		case "about", "auth", "completion", "help", "version":
			original := command.Path[0]
			command.Path = append([]string(nil), command.Path...)
			command.Path[0] = "api-" + original
			*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "import.command-reserved", Path: strings.Join(command.Path, " "), Message: fmt.Sprintf("command root %q is reserved by the generated runtime", original), Hint: "renamed the root to " + command.Path[0]})
		}
	}
	originalID := command.ID
	originalPath := append([]string(nil), command.Path...)
	usedID := map[string]bool{}
	usedPath := map[string]bool{}
	for _, existing := range document.Commands {
		usedID[existing.ID] = true
		usedPath[strings.Join(existing.Path, " ")] = true
	}
	for suffix := 2; usedID[command.ID] || usedPath[strings.Join(command.Path, " ")]; suffix++ {
		command.ID = fmt.Sprintf("%s.%d", originalID, suffix)
		command.Path = append(append([]string(nil), originalPath[:len(originalPath)-1]...), fmt.Sprintf("%s-%d", originalPath[len(originalPath)-1], suffix))
	}
	if command.ID != originalID {
		*diagnostics = append(*diagnostics, model.Diagnostic{Severity: model.SeverityWarning, Code: "import.command-collision", Path: originalID, Message: "command name collided with another operation", Hint: "generated " + strings.Join(command.Path, " ")})
	}
	return command
}

func installAuthScheme(document *model.Document, preferred string, scheme model.AuthScheme) string {
	base := model.Slug(preferred)
	if base == "" {
		base = "auth"
	}
	for suffix := 1; ; suffix++ {
		name := base
		candidate := scheme
		if suffix > 1 {
			name = fmt.Sprintf("%s-%d", base, suffix)
			if candidate.Env != "" {
				candidate.Env = fmt.Sprintf("%s_%d", candidate.Env, suffix)
			}
			if candidate.UsernameEnv != "" {
				candidate.UsernameEnv = fmt.Sprintf("%s_%d", candidate.UsernameEnv, suffix)
			}
			if candidate.PasswordEnv != "" {
				candidate.PasswordEnv = fmt.Sprintf("%s_%d", candidate.PasswordEnv, suffix)
			}
		}
		existing, found := document.Auth[name]
		if found {
			if reflect.DeepEqual(existing, candidate) {
				return name
			}
			continue
		}
		document.Auth[name] = candidate
		return name
	}
}

func sanitizeValue(value any, path string) (any, []string) {
	return sanitizeValueDepth(value, path, 0)
}

func sanitizeValueDepth(value any, path string, depth int) (any, []string) {
	if depth > 128 {
		return nil, []string{path}
	}
	var redacted []string
	switch typed := value.(type) {
	case map[string]any:
		clean := make(map[string]any, len(typed))
		for key, item := range typed {
			itemPath := key
			if path != "" {
				itemPath = path + "." + key
			}
			if looksSensitive(key, stringValue(item)) {
				clean[key] = nil
				redacted = append(redacted, itemPath)
				continue
			}
			sanitized, nested := sanitizeValueDepth(item, itemPath, depth+1)
			clean[key] = sanitized
			redacted = append(redacted, nested...)
		}
		return clean, redacted
	case []any:
		clean := make([]any, len(typed))
		for index, item := range typed {
			itemPath := fmt.Sprintf("%s[%d]", path, index)
			var nested []string
			clean[index], nested = sanitizeValueDepth(item, itemPath, depth+1)
			redacted = append(redacted, nested...)
		}
		return clean, redacted
	case string:
		if looksSensitive(path, typed) {
			return nil, []string{path}
		}
		return typed, nil
	default:
		return value, nil
	}
}
