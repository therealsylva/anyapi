package model

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	APIVersion = "anyapi.dev/v1alpha1"
	KindAPI    = "API"

	maxCommands          = 10_000
	maxServers           = 1_024
	maxAuthSchemes       = 1_024
	maxParameters        = 2_048
	maxCommandPath       = 32
	maxIdentifierBytes   = 128
	maxOperationPathSize = 64 << 10
	maxDescriptionSize   = 64 << 10
)

var (
	identifierPattern      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)
	methodPattern          = regexp.MustCompile("^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*$")
	pathPlaceholderPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_.-]*)\}`)
	environmentPattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	environmentRefPattern  = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	wireNamePattern        = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	serverVariablePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	fingerprintPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Document struct {
	APIVersion    string                `yaml:"apiVersion" json:"apiVersion"`
	Kind          string                `yaml:"kind" json:"kind"`
	Metadata      Metadata              `yaml:"metadata" json:"metadata"`
	DefaultServer string                `yaml:"defaultServer,omitempty" json:"defaultServer,omitempty"`
	Servers       map[string]Server     `yaml:"servers,omitempty" json:"servers,omitempty"`
	Auth          map[string]AuthScheme `yaml:"auth,omitempty" json:"auth,omitempty"`
	Commands      []Command             `yaml:"commands" json:"commands"`
	Import        *ImportMetadata       `yaml:"import,omitempty" json:"import,omitempty"`
}

type Metadata struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Source      string `yaml:"source,omitempty" json:"source,omitempty"`
}

type Server struct {
	URL         string            `yaml:"url" json:"url"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Variables   map[string]string `yaml:"variables,omitempty" json:"variables,omitempty"`
}

type AuthScheme struct {
	Type        string   `yaml:"type" json:"type"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	In          string   `yaml:"in,omitempty" json:"in,omitempty"`
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Env         string   `yaml:"env,omitempty" json:"env,omitempty"`
	UsernameEnv string   `yaml:"usernameEnv,omitempty" json:"usernameEnv,omitempty"`
	PasswordEnv string   `yaml:"passwordEnv,omitempty" json:"passwordEnv,omitempty"`
	Scopes      []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

type Command struct {
	ID          string        `yaml:"id" json:"id"`
	Path        []string      `yaml:"path" json:"path"`
	Summary     string        `yaml:"summary,omitempty" json:"summary,omitempty"`
	Description string        `yaml:"description,omitempty" json:"description,omitempty"`
	Operation   Operation     `yaml:"operation" json:"operation"`
	Parameters  []Parameter   `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Body        *RequestBody  `yaml:"body,omitempty" json:"body,omitempty"`
	Auth        []string      `yaml:"auth,omitempty" json:"auth,omitempty"`
	Responses   []Response    `yaml:"responses,omitempty" json:"responses,omitempty"`
	Source      *SourceRecord `yaml:"source,omitempty" json:"source,omitempty"`
}

type Operation struct {
	Transport string `yaml:"transport" json:"transport"`
	Method    string `yaml:"method" json:"method"`
	Path      string `yaml:"path" json:"path"`
	Server    string `yaml:"server,omitempty" json:"server,omitempty"`
}

type Parameter struct {
	Name        string `yaml:"name" json:"name"`
	Flag        string `yaml:"flag,omitempty" json:"flag,omitempty"`
	In          string `yaml:"in" json:"in"`
	Type        string `yaml:"type,omitempty" json:"type,omitempty"`
	Format      string `yaml:"format,omitempty" json:"format,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Positional  bool   `yaml:"positional,omitempty" json:"positional,omitempty"`
	Sensitive   bool   `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	Default     any    `yaml:"default,omitempty" json:"default,omitempty"`
	Example     any    `yaml:"example,omitempty" json:"example,omitempty"`
	Enum        []any  `yaml:"enum,omitempty" json:"enum,omitempty"`
	Style       string `yaml:"style,omitempty" json:"style,omitempty"`
	Explode     *bool  `yaml:"explode,omitempty" json:"explode,omitempty"`
	JSONPath    string `yaml:"jsonPath,omitempty" json:"jsonPath,omitempty"`
}

type RequestBody struct {
	ContentType string      `yaml:"contentType,omitempty" json:"contentType,omitempty"`
	Required    bool        `yaml:"required,omitempty" json:"required,omitempty"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Fields      []Parameter `yaml:"fields,omitempty" json:"fields,omitempty"`
	Example     any         `yaml:"example,omitempty" json:"example,omitempty"`
}

type Response struct {
	Status      string `yaml:"status" json:"status"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	ContentType string `yaml:"contentType,omitempty" json:"contentType,omitempty"`
}

type ImportMetadata struct {
	Format      string       `yaml:"format" json:"format"`
	Source      string       `yaml:"source,omitempty" json:"source,omitempty"`
	Fingerprint string       `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	Diagnostics []Diagnostic `yaml:"diagnostics,omitempty" json:"diagnostics,omitempty"`
}

type SourceRecord struct {
	Format      string `yaml:"format,omitempty" json:"format,omitempty"`
	OperationID string `yaml:"operationId,omitempty" json:"operationId,omitempty"`
	Pointer     string `yaml:"pointer,omitempty" json:"pointer,omitempty"`
}

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

type Diagnostic struct {
	Severity Severity `yaml:"severity" json:"severity"`
	Code     string   `yaml:"code" json:"code"`
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"`
	Message  string   `yaml:"message" json:"message"`
	Hint     string   `yaml:"hint,omitempty" json:"hint,omitempty"`
}

func (d *Document) Normalize() {
	if d.APIVersion == "" {
		d.APIVersion = APIVersion
	}
	if d.Kind == "" {
		d.Kind = KindAPI
	}
	d.Metadata.Name = Slug(d.Metadata.Name)
	d.Metadata.Version = CleanInline(d.Metadata.Version)
	d.Metadata.Description = CleanText(d.Metadata.Description)
	d.Metadata.Source = CleanInline(d.Metadata.Source)
	if d.Metadata.Version == "" {
		d.Metadata.Version = "1.0.0"
	}
	if d.Servers == nil {
		d.Servers = map[string]Server{}
	}
	if d.Auth == nil {
		d.Auth = map[string]AuthScheme{}
	}
	if d.DefaultServer == "" && len(d.Servers) > 0 {
		keys := make([]string, 0, len(d.Servers))
		for key := range d.Servers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		d.DefaultServer = keys[0]
	}
	for i := range d.Commands {
		cmd := &d.Commands[i]
		cmd.Summary = CleanText(cmd.Summary)
		cmd.Description = CleanText(cmd.Description)
		for j := range cmd.Path {
			cmd.Path[j] = Slug(cmd.Path[j])
		}
		if cmd.ID == "" {
			cmd.ID = strings.Join(cmd.Path, ".")
		}
		cmd.ID = SlugID(cmd.ID)
		cmd.Operation.Transport = strings.ToLower(strings.TrimSpace(cmd.Operation.Transport))
		if cmd.Operation.Transport == "" {
			cmd.Operation.Transport = "http"
		}
		cmd.Operation.Method = strings.ToUpper(strings.TrimSpace(cmd.Operation.Method))
		for j := range cmd.Parameters {
			normalizeParameter(&cmd.Parameters[j])
		}
		if cmd.Body != nil {
			cmd.Body.Description = CleanText(cmd.Body.Description)
			if cmd.Body.ContentType == "" {
				cmd.Body.ContentType = "application/json"
			}
			for j := range cmd.Body.Fields {
				normalizeParameter(&cmd.Body.Fields[j])
				cmd.Body.Fields[j].In = "body"
			}
		}
		for j := range cmd.Responses {
			cmd.Responses[j].Description = CleanText(cmd.Responses[j].Description)
		}
		if cmd.Source != nil {
			cmd.Source.Format = strings.ToLower(strings.TrimSpace(cmd.Source.Format))
			cmd.Source.OperationID = CleanInline(cmd.Source.OperationID)
			cmd.Source.Pointer = CleanInline(cmd.Source.Pointer)
		}
	}
	for name, server := range d.Servers {
		server.Description = CleanText(server.Description)
		d.Servers[name] = server
	}
	for name, scheme := range d.Auth {
		scheme.Description = CleanText(scheme.Description)
		switch strings.ToLower(strings.TrimSpace(scheme.Type)) {
		case "apikey":
			scheme.Type = "apiKey"
		case "openidconnect":
			scheme.Type = "openidconnect"
		default:
			scheme.Type = strings.ToLower(strings.TrimSpace(scheme.Type))
		}
		scheme.In = strings.ToLower(strings.TrimSpace(scheme.In))
		scheme.Env = strings.TrimSpace(scheme.Env)
		scheme.UsernameEnv = strings.TrimSpace(scheme.UsernameEnv)
		scheme.PasswordEnv = strings.TrimSpace(scheme.PasswordEnv)
		for index := range scheme.Scopes {
			scheme.Scopes[index] = CleanInline(scheme.Scopes[index])
		}
		d.Auth[name] = scheme
	}
	if d.Import != nil {
		d.Import.Format = strings.ToLower(strings.TrimSpace(d.Import.Format))
		d.Import.Source = CleanInline(d.Import.Source)
		d.Import.Fingerprint = strings.TrimSpace(d.Import.Fingerprint)
		if len(d.Import.Diagnostics) > maxCommands+1 {
			d.Import.Diagnostics = d.Import.Diagnostics[:maxCommands+1]
		}
		for index := range d.Import.Diagnostics {
			d.Import.Diagnostics[index] = CleanDiagnostic(d.Import.Diagnostics[index])
		}
	}
}

func normalizeParameter(parameter *Parameter) {
	parameter.Name = strings.TrimSpace(parameter.Name)
	if parameter.Flag == "" {
		parameter.Flag = Slug(parameter.Name)
	} else {
		parameter.Flag = Slug(parameter.Flag)
	}
	parameter.In = strings.ToLower(strings.TrimSpace(parameter.In))
	parameter.Type = strings.ToLower(strings.TrimSpace(parameter.Type))
	parameter.Description = CleanText(parameter.Description)
	if parameter.Type == "" {
		parameter.Type = "string"
	}
	if sensitiveModelName(parameter.Name) {
		parameter.Sensitive = true
	}
}

func CleanText(value string) string {
	return strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' {
			return character
		}
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return -1
		}
		return character
	}, value)
}

func CleanInline(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return -1
		}
		return character
	}, value)
}

func CleanDiagnostic(diagnostic Diagnostic) Diagnostic {
	diagnostic.Code = CleanInline(diagnostic.Code)
	diagnostic.Path = CleanInline(diagnostic.Path)
	diagnostic.Message = CleanInline(diagnostic.Message)
	diagnostic.Hint = CleanInline(diagnostic.Hint)
	return diagnostic
}

func (d Document) Validate() []Diagnostic {
	var diagnostics []Diagnostic
	add := func(severity Severity, code, path, message, hint string) {
		diagnostics = append(diagnostics, Diagnostic{Severity: severity, Code: code, Path: path, Message: message, Hint: hint})
	}
	if d.APIVersion != APIVersion {
		add(SeverityError, "document.api-version", "apiVersion", fmt.Sprintf("unsupported API version %q", d.APIVersion), "use "+APIVersion)
	}
	if d.Kind != KindAPI {
		add(SeverityError, "document.kind", "kind", fmt.Sprintf("unsupported document kind %q", d.Kind), "use API")
	}
	structuralLimitExceeded := false
	for _, check := range []struct {
		size  int
		limit int
		code  string
		path  string
		label string
	}{
		{len(d.Commands), maxCommands, "commands.limit", "commands", "commands"},
		{len(d.Servers), maxServers, "servers.limit", "servers", "servers"},
		{len(d.Auth), maxAuthSchemes, "auth.limit", "auth", "authentication schemes"},
	} {
		if check.size > check.limit {
			add(SeverityError, check.code, check.path, fmt.Sprintf("document contains %d %s; the limit is %d", check.size, check.label, check.limit), "split the API into smaller manifests")
			structuralLimitExceeded = true
		}
	}
	if structuralLimitExceeded {
		sortDiagnostics(diagnostics)
		return diagnostics
	}
	if d.Metadata.Name == "" || !identifierPattern.MatchString(d.Metadata.Name) {
		add(SeverityError, "metadata.name", "metadata.name", "name must be a lowercase CLI identifier", "use letters, digits, dashes, underscores, or dots")
	}
	if len(d.Metadata.Name) > maxIdentifierBytes {
		add(SeverityError, "metadata.name-length", "metadata.name", fmt.Sprintf("name exceeds %d bytes", maxIdentifierBytes), "use a shorter CLI name")
	}
	if len(d.Metadata.Description) > maxDescriptionSize {
		add(SeverityError, "metadata.description-length", "metadata.description", fmt.Sprintf("description exceeds %d bytes", maxDescriptionSize), "shorten the description")
	}
	if len(d.Metadata.Version) > 1<<10 {
		add(SeverityError, "metadata.version-length", "metadata.version", "version exceeds 1024 bytes", "use a shorter version")
	}
	if len(d.Metadata.Source) > maxOperationPathSize {
		add(SeverityError, "metadata.source-length", "metadata.source", fmt.Sprintf("source identifier exceeds %d bytes", maxOperationPathSize), "use a shorter source identifier")
	}
	if len(d.Commands) == 0 {
		add(SeverityError, "commands.empty", "commands", "the API has no commands", "import at least one operation")
	}
	if d.DefaultServer != "" {
		if _, ok := d.Servers[d.DefaultServer]; !ok {
			add(SeverityError, "servers.default-missing", "defaultServer", "default server is not defined", "add the server or choose an existing server")
		}
	}
	if d.Import != nil {
		if len(d.Import.Source) > maxOperationPathSize {
			add(SeverityError, "import.source-length", "import.source", fmt.Sprintf("import source exceeds %d bytes", maxOperationPathSize), "use a shorter source identifier")
		}
		switch d.Import.Format {
		case "curl", "openapi", "postman":
		default:
			add(SeverityError, "import.format", "import.format", fmt.Sprintf("unsupported import format %q", d.Import.Format), "use curl, openapi, or postman")
		}
		if d.Import.Fingerprint != "" && !fingerprintPattern.MatchString(d.Import.Fingerprint) {
			add(SeverityError, "import.fingerprint", "import.fingerprint", "import fingerprint is not a lowercase SHA-256 value", "use sha256 followed by 64 hexadecimal characters")
		}
		if len(d.Import.Diagnostics) > maxCommands {
			add(SeverityError, "import.diagnostics-limit", "import.diagnostics", fmt.Sprintf("import metadata contains more than %d diagnostics", maxCommands), "reduce stored diagnostics")
		} else {
			for index, diagnostic := range d.Import.Diagnostics {
				path := fmt.Sprintf("import.diagnostics[%d]", index)
				if diagnostic.Severity != SeverityInfo && diagnostic.Severity != SeverityWarning && diagnostic.Severity != SeverityError {
					add(SeverityError, "import.diagnostic-severity", path+".severity", fmt.Sprintf("invalid diagnostic severity %q", diagnostic.Severity), "use info, warning, or error")
				}
				if diagnostic.Code == "" || len(diagnostic.Code) > maxIdentifierBytes || len(diagnostic.Path) > maxOperationPathSize || len(diagnostic.Message) > maxDescriptionSize || len(diagnostic.Hint) > maxDescriptionSize {
					add(SeverityError, "import.diagnostic-shape", path, "diagnostic fields are empty or exceed safety limits", "use a short non-empty code and bounded text fields")
				}
			}
		}
	}
	for name, server := range d.Servers {
		path := "servers." + name
		if !identifierPattern.MatchString(name) {
			add(SeverityError, "server.name", path, fmt.Sprintf("invalid server name %q", name), "use a lowercase CLI identifier")
		}
		if len(name) > maxIdentifierBytes {
			add(SeverityError, "server.name-length", path, fmt.Sprintf("server name exceeds %d bytes", maxIdentifierBytes), "use a shorter server name")
		}
		if len(server.URL) > maxOperationPathSize {
			add(SeverityError, "server.url-length", path+".url", fmt.Sprintf("server URL exceeds %d bytes", maxOperationPathSize), "use a shorter base URL")
			continue
		}
		if len(server.Description) > maxDescriptionSize {
			add(SeverityError, "server.description-length", path+".description", fmt.Sprintf("server description exceeds %d bytes", maxDescriptionSize), "shorten the description")
		}
		if len(server.Variables) > maxParameters {
			add(SeverityError, "server.variables-limit", path+".variables", fmt.Sprintf("server contains more than %d variables", maxParameters), "reduce server variables")
			continue
		}
		expanded := server.URL
		for variable, value := range server.Variables {
			expanded = strings.ReplaceAll(expanded, "{"+variable+"}", value)
		}
		parsed, err := url.Parse(expanded)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			add(SeverityError, "server.url", "servers."+name+".url", "server URL is not an absolute HTTP(S) URL", "include an http or https scheme and host")
		} else {
			if parsed.User != nil {
				add(SeverityError, "server.credentials", path+".url", "server URLs cannot contain credentials", "use an authentication scheme")
			}
			if parsed.Fragment != "" {
				add(SeverityError, "server.fragment", path+".url", "server URLs cannot contain fragments", "remove the #fragment")
			}
			if parsed.RawQuery != "" {
				add(SeverityError, "server.query", path+".url", "server URLs cannot contain query parameters", "move query values into command parameters")
			}
		}
		if strings.Contains(expanded, "{") || strings.Contains(expanded, "}") {
			add(SeverityError, "server.variable-unresolved", path+".url", "server URL contains an unresolved variable", "add a default under server.variables")
		}
		for variable, value := range server.Variables {
			if !serverVariablePattern.MatchString(variable) || len(variable) > maxIdentifierBytes {
				add(SeverityError, "server.variable-name", path+".variables."+variable, "server variable name is invalid or too long", "use letters, digits, dots, dashes, or underscores")
			}
			if sensitiveModelName(variable) && value != "" {
				add(SeverityError, "server.variable-sensitive", path+".variables."+variable, "server variables cannot contain credential-like defaults", "move credentials into an authentication scheme")
			}
			if len(value) > 4<<10 || CleanInline(value) != value {
				add(SeverityError, "server.variable-value", path+".variables."+variable, "server variable default is too long or contains control characters", "use a short printable URL component")
			}
		}
	}
	for name, scheme := range d.Auth {
		path := "auth." + name
		if !identifierPattern.MatchString(name) {
			add(SeverityError, "auth.name", path, fmt.Sprintf("invalid authentication scheme name %q", name), "use a lowercase CLI identifier")
		}
		if len(name) > maxIdentifierBytes {
			add(SeverityError, "auth.name-length", path, fmt.Sprintf("authentication scheme name exceeds %d bytes", maxIdentifierBytes), "use a shorter name")
		}
		if len(scheme.Description) > maxDescriptionSize {
			add(SeverityError, "auth.description-length", path+".description", fmt.Sprintf("authentication description exceeds %d bytes", maxDescriptionSize), "shorten the description")
		}
		if len(scheme.Scopes) > maxParameters {
			add(SeverityError, "auth.scopes-limit", path+".scopes", fmt.Sprintf("authentication scheme contains more than %d scopes", maxParameters), "reduce the scope list")
		}
		scopeSet := map[string]struct{}{}
		for index, scope := range scheme.Scopes {
			if len(scope) > 4<<10 || strings.ContainsAny(scope, "\r\n\t") || CleanText(scope) != scope {
				add(SeverityError, "auth.scope", fmt.Sprintf("%s.scopes[%d]", path, index), "authentication scope is too long or contains unsafe terminal controls", "use a short printable scope")
			}
			if _, duplicate := scopeSet[scope]; duplicate {
				add(SeverityError, "auth.scope-duplicate", fmt.Sprintf("%s.scopes[%d]", path, index), fmt.Sprintf("duplicate authentication scope %q", scope), "list each scope once")
			}
			scopeSet[scope] = struct{}{}
		}
		switch strings.ToLower(scheme.Type) {
		case "bearer", "oauth2", "openidconnect", "basic":
		case "apikey":
			if scheme.Name == "" {
				add(SeverityError, "auth.api-key-name", path+".name", "API key name is required", "set the header, query, or cookie name")
			}
			if scheme.In != "header" && scheme.In != "query" && scheme.In != "cookie" {
				add(SeverityError, "auth.api-key-location", path+".in", fmt.Sprintf("invalid API key location %q", scheme.In), "use header, query, or cookie")
			}
			if (scheme.In == "header" || scheme.In == "cookie") && !wireNamePattern.MatchString(scheme.Name) {
				add(SeverityError, "auth.api-key-wire-name", path+".name", fmt.Sprintf("invalid %s name %q", scheme.In, scheme.Name), "use a valid HTTP token name")
			}
		default:
			add(SeverityError, "auth.type", path+".type", fmt.Sprintf("unsupported authentication type %q", scheme.Type), "use bearer, oauth2, apiKey, or basic")
		}
		if len(scheme.Name) > maxIdentifierBytes*2 || CleanInline(scheme.Name) != scheme.Name {
			add(SeverityError, "auth.wire-name", path+".name", "authentication wire name is too long or contains control characters", "use a short printable HTTP parameter name")
		}
		for field, value := range map[string]string{"env": scheme.Env, "usernameEnv": scheme.UsernameEnv, "passwordEnv": scheme.PasswordEnv} {
			if value != "" && !environmentPattern.MatchString(value) {
				add(SeverityError, "auth.env", path+"."+field, fmt.Sprintf("invalid environment variable name %q", value), "use letters, digits, and underscores")
			}
		}
	}
	seenID := map[string]struct{}{}
	seenPath := map[string]struct{}{}
	reservedRoot := map[string]bool{"about": true, "auth": true, "completion": true, "help": true, "version": true}
	for i, command := range d.Commands {
		base := fmt.Sprintf("commands[%d]", i)
		commandLimitExceeded := false
		for _, check := range []struct {
			size  int
			limit int
			code  string
			path  string
			label string
		}{
			{len(command.Path), maxCommandPath, "command.path-limit", base + ".path", "command path segments"},
			{len(command.Parameters), maxParameters, "command.parameters-limit", base + ".parameters", "parameters"},
			{len(command.Auth), maxAuthSchemes, "command.auth-limit", base + ".auth", "authentication requirements"},
			{len(command.Responses), maxParameters, "command.responses-limit", base + ".responses", "responses"},
		} {
			if check.size > check.limit {
				add(SeverityError, check.code, check.path, fmt.Sprintf("command contains %d %s; the limit is %d", check.size, check.label, check.limit), "reduce the command definition")
				commandLimitExceeded = true
			}
		}
		if command.Body != nil && len(command.Body.Fields) > maxParameters {
			add(SeverityError, "body.fields-limit", base+".body.fields", fmt.Sprintf("request body contains more than %d fields", maxParameters), "reduce or model the body with --body")
			commandLimitExceeded = true
		}
		if commandLimitExceeded {
			continue
		}
		if command.ID == "" || !identifierPattern.MatchString(command.ID) {
			add(SeverityError, "command.id", base+".id", fmt.Sprintf("invalid command ID %q", command.ID), "use a stable lowercase dotted identifier")
		}
		if command.Source != nil {
			switch command.Source.Format {
			case "", "curl", "openapi", "postman":
			default:
				add(SeverityError, "source.format", base+".source.format", fmt.Sprintf("unsupported source format %q", command.Source.Format), "use curl, openapi, or postman")
			}
			if len(command.Source.OperationID) > 4<<10 || len(command.Source.Pointer) > maxOperationPathSize {
				add(SeverityError, "source.length", base+".source", "source provenance exceeds safety limits", "shorten source metadata")
			}
		}
		if len(command.ID) > maxIdentifierBytes {
			add(SeverityError, "command.id-length", base+".id", fmt.Sprintf("command ID exceeds %d bytes", maxIdentifierBytes), "use a shorter command ID")
		}
		if len(command.Summary) > maxDescriptionSize || len(command.Description) > maxDescriptionSize {
			add(SeverityError, "command.description-length", base, fmt.Sprintf("command summary or description exceeds %d bytes", maxDescriptionSize), "shorten command documentation")
		}
		if _, ok := seenID[command.ID]; ok {
			add(SeverityError, "command.id-duplicate", base+".id", fmt.Sprintf("duplicate command ID %q", command.ID), "give every operation a unique ID")
		}
		seenID[command.ID] = struct{}{}
		if len(command.Path) == 0 {
			add(SeverityError, "command.path-empty", base+".path", "command path cannot be empty", "provide at least one command segment")
		} else {
			for j, segment := range command.Path {
				if !identifierPattern.MatchString(segment) {
					add(SeverityError, "command.path-segment", fmt.Sprintf("%s.path[%d]", base, j), fmt.Sprintf("invalid command path segment %q", segment), "use a lowercase CLI identifier")
				}
				if len(segment) > maxIdentifierBytes {
					add(SeverityError, "command.path-segment-length", fmt.Sprintf("%s.path[%d]", base, j), fmt.Sprintf("command path segment exceeds %d bytes", maxIdentifierBytes), "use a shorter segment")
				}
			}
			joined := strings.Join(command.Path, " ")
			if _, ok := seenPath[joined]; ok {
				add(SeverityError, "command.path-duplicate", base+".path", fmt.Sprintf("duplicate CLI path %q", joined), "rename one command")
			}
			seenPath[joined] = struct{}{}
			if reservedRoot[command.Path[0]] {
				add(SeverityError, "command.path-reserved", base+".path", fmt.Sprintf("%q is reserved by the generated runtime", command.Path[0]), "rename the top-level command")
			}
		}
		if command.Operation.Transport != "http" {
			add(SeverityError, "operation.transport", base+".operation.transport", fmt.Sprintf("unsupported transport %q", command.Operation.Transport), "HTTP is supported in this release")
		}
		if !methodPattern.MatchString(command.Operation.Method) {
			add(SeverityError, "operation.method", base+".operation.method", "HTTP method is required", "set GET, POST, PUT, PATCH, DELETE, or another HTTP method")
		}
		if !strings.HasPrefix(command.Operation.Path, "/") {
			add(SeverityError, "operation.path", base+".operation.path", "HTTP path must begin with /", "use an absolute API path such as /users/{id}")
		}
		if len(command.Operation.Path) > maxOperationPathSize {
			add(SeverityError, "operation.path-length", base+".operation.path", fmt.Sprintf("HTTP operation path exceeds %d bytes", maxOperationPathSize), "use a shorter request path")
		}
		if strings.ContainsAny(command.Operation.Path, "\r\n?#") {
			add(SeverityError, "operation.path-components", base+".operation.path", "HTTP operation path cannot contain controls, a query, or a fragment", "model query values as parameters and percent-encode literal ? or # characters")
		}
		if command.Operation.Server != "" {
			if _, exists := d.Servers[command.Operation.Server]; !exists {
				parsed, err := url.Parse(command.Operation.Server)
				if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
					add(SeverityError, "operation.server", base+".operation.server", "operation server is neither declared nor a valid credential-free HTTP(S) URL", "use a server name or absolute HTTP(S) URL")
				}
			}
		}
		parameterNames := map[string]struct{}{}
		flagNames := map[string]struct{}{}
		pathParameters := map[string]struct{}{}
		positionalEnded := false
		for j, parameter := range command.Parameters {
			path := fmt.Sprintf("%s.parameters[%d]", base, j)
			validateParameter(&diagnostics, parameter, path, false)
			if _, ok := parameterNames[parameter.Name]; ok {
				add(SeverityError, "parameter.duplicate", path, fmt.Sprintf("duplicate parameter %q", parameter.Name), "merge or rename the parameter")
			}
			parameterNames[parameter.Name] = struct{}{}
			if _, ok := flagNames[parameter.Flag]; ok {
				add(SeverityError, "parameter.flag-duplicate", path+".flag", fmt.Sprintf("duplicate flag --%s", parameter.Flag), "assign a unique flag name")
			}
			flagNames[parameter.Flag] = struct{}{}
			if !validRuntimeParameterLocation(parameter.In) {
				add(SeverityError, "parameter.location", path+".in", fmt.Sprintf("unsupported parameter location %q", parameter.In), "use path, query, header, cookie, or body")
			}
			if parameter.In == "path" {
				pathParameters[parameter.Name] = struct{}{}
				if !strings.Contains(command.Operation.Path, "{"+parameter.Name+"}") {
					add(SeverityError, "parameter.path-unused", path, fmt.Sprintf("path parameter %q has no matching placeholder", parameter.Name), "add {"+parameter.Name+"} to the operation path")
				}
				if !parameter.Required {
					add(SeverityError, "parameter.path-optional", path+".required", "path parameters must be required", "set required: true")
				}
			}
			if parameter.Positional {
				if positionalEnded && parameter.Required {
					add(SeverityError, "parameter.positional-order", path, "required positional parameters must precede optional positional parameters", "reorder the parameters or make them flags")
				}
				if !parameter.Required {
					positionalEnded = true
				}
			}
		}
		for _, match := range pathPlaceholderPattern.FindAllStringSubmatch(command.Operation.Path, -1) {
			if _, ok := pathParameters[match[1]]; !ok {
				add(SeverityError, "operation.path-parameter-missing", base+".operation.path", fmt.Sprintf("path placeholder %q has no parameter", match[1]), "add a required path parameter")
			}
		}
		if command.Body != nil {
			if len(command.Body.ContentType) > 1<<10 {
				add(SeverityError, "body.content-type-length", base+".body.contentType", "request body content type exceeds 1024 bytes", "use a shorter media type")
			}
			if len(command.Body.Description) > maxDescriptionSize {
				add(SeverityError, "body.description-length", base+".body.description", fmt.Sprintf("request body description exceeds %d bytes", maxDescriptionSize), "shorten the description")
			}
			if _, _, err := mime.ParseMediaType(command.Body.ContentType); err != nil {
				add(SeverityError, "body.content-type", base+".body.contentType", "request body content type is invalid", "use an HTTP media type such as application/json")
			}
			if valueNestingExceeds(command.Body.Example, 0) {
				add(SeverityError, "body.example-depth", base+".body.example", "request body example exceeds the maximum nesting depth", "flatten the example to at most 128 levels")
			} else {
				for _, secretPath := range sensitiveExamplePaths(command.Body.Example, base+".body.example") {
					add(SeverityError, "body.example-sensitive", secretPath, "request body example appears to contain a credential", "remove the value and provide it at runtime")
				}
			}
			bodyFlags := map[string]struct{}{}
			bodyPaths := map[string]struct{}{}
			for j, field := range command.Body.Fields {
				path := fmt.Sprintf("%s.body.fields[%d]", base, j)
				validateParameter(&diagnostics, field, path, true)
				if _, ok := bodyFlags[field.Flag]; ok {
					add(SeverityError, "body.flag-duplicate", path+".flag", fmt.Sprintf("duplicate body flag --%s", field.Flag), "assign a unique body field flag")
				}
				bodyFlags[field.Flag] = struct{}{}
				if _, ok := flagNames[field.Flag]; ok {
					add(SeverityWarning, "body.flag-collision", path+".flag", fmt.Sprintf("body flag --%s collides with another parameter", field.Flag), "the runtime will expose it as --body-"+field.Flag)
				}
				flagNames[field.Flag] = struct{}{}
				jsonPath := strings.Trim(firstNonEmpty(field.JSONPath, field.Name), ".")
				if jsonPath == "" || strings.Contains(jsonPath, "..") || strings.ContainsAny(jsonPath, "\r\n\t") || CleanText(jsonPath) != jsonPath {
					add(SeverityError, "body.json-path", path+".jsonPath", "JSON path must contain non-empty dot-separated fields", "use a path such as profile.displayName")
					continue
				}
				for existing := range bodyPaths {
					if jsonPath == existing || strings.HasPrefix(jsonPath, existing+".") || strings.HasPrefix(existing, jsonPath+".") {
						add(SeverityError, "body.json-path-conflict", path+".jsonPath", fmt.Sprintf("JSON path %q conflicts with %q", jsonPath, existing), "give each body field a distinct non-overlapping JSON path")
					}
				}
				bodyPaths[jsonPath] = struct{}{}
			}
		}
		for j, response := range command.Responses {
			path := fmt.Sprintf("%s.responses[%d]", base, j)
			if response.Status == "" || len(response.Status) > maxIdentifierBytes {
				add(SeverityError, "response.status", path+".status", "response status must be between 1 and 128 bytes", "use an HTTP status code, range, or default")
			}
			if len(response.Description) > maxDescriptionSize {
				add(SeverityError, "response.description-length", path+".description", fmt.Sprintf("response description exceeds %d bytes", maxDescriptionSize), "shorten the description")
			}
			if response.ContentType != "" {
				if len(response.ContentType) > 1<<10 {
					add(SeverityError, "response.content-type-length", path+".contentType", "response content type exceeds 1024 bytes", "use a shorter media type")
				} else if _, _, err := mime.ParseMediaType(response.ContentType); err != nil {
					add(SeverityError, "response.content-type", path+".contentType", "response content type is invalid", "use an HTTP media type such as application/json")
				}
			}
		}
		authSet := map[string]struct{}{}
		for _, authName := range command.Auth {
			if _, ok := d.Auth[authName]; !ok {
				add(SeverityError, "auth.undefined", base+".auth", fmt.Sprintf("undefined authentication scheme %q", authName), "define the scheme under auth")
			}
			if _, duplicate := authSet[authName]; duplicate {
				add(SeverityError, "auth.duplicate", base+".auth", fmt.Sprintf("duplicate authentication scheme %q", authName), "list each scheme once")
			}
			authSet[authName] = struct{}{}
		}
	}
	sortDiagnostics(diagnostics)
	return diagnostics
}

func sortDiagnostics(diagnostics []Diagnostic) {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		if diagnostics[i].Severity != diagnostics[j].Severity {
			return severityRank(diagnostics[i].Severity) > severityRank(diagnostics[j].Severity)
		}
		if diagnostics[i].Path != diagnostics[j].Path {
			return diagnostics[i].Path < diagnostics[j].Path
		}
		return diagnostics[i].Code < diagnostics[j].Code
	})
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityError:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}

func validRuntimeParameterLocation(location string) bool {
	switch location {
	case "path", "query", "header", "cookie":
		return true
	default:
		return false
	}
}

func validateParameter(diagnostics *[]Diagnostic, parameter Parameter, path string, body bool) {
	add := func(severity Severity, code, suffix, message, hint string) {
		*diagnostics = append(*diagnostics, Diagnostic{Severity: severity, Code: code, Path: path + suffix, Message: message, Hint: hint})
	}
	if parameter.Name == "" {
		add(SeverityError, "parameter.name", ".name", "parameter name cannot be empty", "set the wire parameter name")
	}
	if len(parameter.Name) > maxIdentifierBytes*2 {
		add(SeverityError, "parameter.name-length", ".name", fmt.Sprintf("parameter name exceeds %d bytes", maxIdentifierBytes*2), "use a shorter wire name")
	}
	if CleanInline(parameter.Name) != parameter.Name {
		add(SeverityError, "parameter.name-text", ".name", "parameter name contains terminal control characters", "use a printable wire name")
	}
	if (parameter.In == "header" || parameter.In == "cookie") && !wireNamePattern.MatchString(parameter.Name) {
		add(SeverityError, "parameter.wire-name", ".name", fmt.Sprintf("invalid %s name %q", parameter.In, parameter.Name), "use a valid HTTP token name")
	}
	if !identifierPattern.MatchString(parameter.Flag) {
		add(SeverityError, "parameter.flag", ".flag", fmt.Sprintf("invalid CLI flag %q", parameter.Flag), "use a lowercase CLI identifier")
	}
	if len(parameter.Flag) > maxIdentifierBytes {
		add(SeverityError, "parameter.flag-length", ".flag", fmt.Sprintf("parameter flag exceeds %d bytes", maxIdentifierBytes), "use a shorter flag")
	}
	if len(parameter.Description) > maxDescriptionSize {
		add(SeverityError, "parameter.description-length", ".description", fmt.Sprintf("parameter description exceeds %d bytes", maxDescriptionSize), "shorten the description")
	}
	if len(parameter.Format) > maxIdentifierBytes {
		add(SeverityError, "parameter.format-length", ".format", fmt.Sprintf("parameter format exceeds %d bytes", maxIdentifierBytes), "use a shorter format name")
	}
	if len(parameter.JSONPath) > 4<<10 {
		add(SeverityError, "parameter.json-path-length", ".jsonPath", "jsonPath exceeds 4096 bytes", "use a shorter JSON path")
	}
	if len(parameter.Enum) > maxParameters {
		add(SeverityError, "parameter.enum-limit", ".enum", fmt.Sprintf("parameter enum contains more than %d values", maxParameters), "reduce the enum")
	}
	isSensitive := parameter.Sensitive || sensitiveModelName(parameter.Name)
	for index, value := range parameter.Enum {
		suffix := fmt.Sprintf(".enum[%d]", index)
		if !scalarEnumValue(value) {
			add(SeverityError, "parameter.enum-type", suffix, "enum values must be scalar strings, numbers, or booleans", "replace nested enum values with scalar values")
			continue
		}
		text := fmt.Sprint(value)
		if len(text) > 4<<10 || strings.ContainsAny(text, "\r\n\t") || CleanText(text) != text {
			add(SeverityError, "parameter.enum-text", suffix, "enum value is too long or contains unsafe terminal control characters", "use a short printable scalar value")
		}
		if isSensitive || sensitiveTextValue(text) {
			add(SeverityError, "parameter.enum-sensitive", suffix, "sensitive parameters cannot contain compiled enum values", "remove the enum and provide the value at runtime")
		}
	}
	if body {
		if parameter.In != "body" {
			add(SeverityError, "body.location", ".in", fmt.Sprintf("body field has location %q", parameter.In), "use body")
		}
		if parameter.Positional {
			add(SeverityError, "body.positional", ".positional", "body fields cannot be positional arguments", "remove positional or model the value as a path parameter")
		}
		if parameter.Explode != nil {
			add(SeverityError, "body.explode", ".explode", "body field explode metadata is not executable", "remove explode and use jsonPath for JSON nesting")
		}
	} else if parameter.In == "body" {
		add(SeverityError, "parameter.body-location", ".in", "body parameters belong under command.body.fields", "move the parameter into the request body")
	} else if parameter.JSONPath != "" {
		add(SeverityError, "parameter.json-path", ".jsonPath", "jsonPath only applies to request body fields", "remove jsonPath or move the parameter under body.fields")
	}
	if parameter.Style != "" && !validParameterStyle(parameter.In, parameter.Style, parameter.Type) {
		add(SeverityError, "parameter.style", ".style", fmt.Sprintf("unsupported %s style %q", parameter.In, parameter.Style), "use a serialization style supported for this parameter location and type")
	}
	switch parameter.Type {
	case "string", "integer", "number", "boolean", "array", "object":
	default:
		add(SeverityError, "parameter.type", ".type", fmt.Sprintf("unsupported parameter type %q", parameter.Type), "use string, integer, number, boolean, array, or object")
	}
	if valueNestingExceeds(parameter.Default, 0) {
		add(SeverityError, "parameter.default-depth", ".default", "parameter default exceeds the maximum nesting depth", "flatten the value to at most 128 levels")
	} else if isSensitive && parameter.Default != nil {
		add(SeverityError, "parameter.sensitive-default", ".default", "sensitive parameters cannot have compiled defaults", "use an environment variable, keyring credential, or runtime flag")
	} else {
		for _, secretPath := range sensitiveExamplePaths(parameter.Default, ".default") {
			add(SeverityError, "parameter.secret-default", secretPath, "parameter default appears to contain a credential", "remove the value and provide it at runtime")
		}
	}
	if valueNestingExceeds(parameter.Example, 0) {
		add(SeverityError, "parameter.example-depth", ".example", "parameter example exceeds the maximum nesting depth", "flatten the value to at most 128 levels")
	} else if isSensitive && parameter.Example != nil {
		add(SeverityError, "parameter.sensitive-example", ".example", "sensitive parameters cannot have compiled examples", "remove the example")
	} else {
		for _, secretPath := range sensitiveExamplePaths(parameter.Example, ".example") {
			add(SeverityError, "parameter.secret-example", secretPath, "parameter example appears to contain a credential", "remove the example")
		}
	}
	for _, value := range interfaceStringsForValidation(parameter.Default) {
		if strings.ContainsAny(value, "\r\n") && parameter.In == "header" {
			add(SeverityError, "parameter.header-newline", ".default", "header defaults cannot contain newlines", "remove the newline")
			break
		}
	}
	if parameter.In == "path" && hasEnvironmentReference(parameter.Default) {
		add(SeverityError, "parameter.path-env-default", ".default", "path parameter defaults cannot expand environment variables", "provide the path value explicitly at runtime")
	}
}

func sensitiveExamplePaths(value any, path string) []string {
	return sensitiveExamplePathsDepth(value, path, 0)
}

func sensitiveExamplePathsDepth(value any, path string, depth int) []string {
	if value == nil {
		return nil
	}
	if depth > 128 {
		return nil
	}
	if text, ok := value.(string); ok && json.Valid([]byte(text)) {
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) == nil {
			return sensitiveExamplePathsDepth(decoded, path, depth+1)
		}
	}
	if text, ok := value.(string); ok && sensitiveTextValue(text) {
		return []string{path}
	}
	var paths []string
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			itemPath := path + "." + key
			if sensitiveModelName(key) && item != nil && fmt.Sprint(item) != "" {
				paths = append(paths, itemPath)
				continue
			}
			paths = append(paths, sensitiveExamplePathsDepth(item, itemPath, depth+1)...)
		}
	case []any:
		for index, item := range typed {
			paths = append(paths, sensitiveExamplePathsDepth(item, fmt.Sprintf("%s[%d]", path, index), depth+1)...)
		}
	case []string:
		for index, item := range typed {
			paths = append(paths, sensitiveExamplePathsDepth(item, fmt.Sprintf("%s[%d]", path, index), depth+1)...)
		}
	}
	sort.Strings(paths)
	return paths
}

func valueNestingExceeds(value any, depth int) bool {
	if depth > 128 {
		return true
	}
	if text, ok := value.(string); ok && json.Valid([]byte(text)) {
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) == nil {
			return valueNestingExceeds(decoded, depth+1)
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, item := range typed {
			if valueNestingExceeds(item, depth+1) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if valueNestingExceeds(item, depth+1) {
				return true
			}
		}
	}
	return false
}

func sensitiveModelName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"authorization", "credential", "api-key", "api_key", "apikey", "access-key", "access_key", "secret", "token", "password", "passwd", "private-key", "private_key", "cookie", "session"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sensitiveTextValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	for _, marker := range []string{
		"authorization:", "bearer ", "password=", "password:", "passwd=", "api_key=", "apikey=",
		"access_token=", "access-token=", "refresh_token=", "client_secret=", "private_key",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, prefix := range []string{"sk_", "pk_live_", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if strings.HasPrefix(trimmed, "AKIA") && len(trimmed) >= 16 {
		return true
	}
	for _, match := range environmentRefPattern.FindAllStringSubmatch(trimmed, -1) {
		if sensitiveModelName(match[1]) {
			return true
		}
	}
	return strings.Count(trimmed, ".") == 2 && strings.HasPrefix(trimmed, "eyJ") && len(trimmed) > 40
}

func hasEnvironmentReference(value any) bool {
	for _, text := range interfaceStringsForValidation(value) {
		if environmentRefPattern.MatchString(text) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func validParameterStyle(location, style, parameterType string) bool {
	switch location {
	case "path":
		return style == "simple" || style == "label" || style == "matrix"
	case "query":
		if style == "deepObject" {
			return parameterType == "object"
		}
		if style == "spaceDelimited" || style == "pipeDelimited" {
			return parameterType == "array"
		}
		return style == "form"
	case "header":
		return style == "simple"
	case "cookie":
		return style == "form"
	case "body":
		return false
	default:
		return false
	}
}

func interfaceStringsForValidation(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, fmt.Sprint(item))
		}
		return result
	default:
		return nil
	}
}

func scalarEnumValue(value any) bool {
	switch value.(type) {
	case string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return true
	default:
		return false
	}
}

func (d Document) HasErrors() bool {
	for _, diagnostic := range d.AllDiagnostics() {
		if diagnostic.Severity == SeverityError {
			return true
		}
	}
	return false
}

func (d Document) AllDiagnostics() []Diagnostic {
	diagnostics := append([]Diagnostic(nil), d.Validate()...)
	if d.Import != nil {
		limit := len(d.Import.Diagnostics)
		if limit > maxCommands {
			limit = maxCommands
		}
		diagnostics = append(diagnostics, d.Import.Diagnostics[:limit]...)
	}
	return diagnostics
}

func (d Document) Command(idOrPath string) (*Command, bool) {
	needle := strings.TrimSpace(idOrPath)
	for i := range d.Commands {
		if d.Commands[i].ID == needle || strings.Join(d.Commands[i].Path, " ") == needle || strings.Join(d.Commands[i].Path, ".") == needle {
			return &d.Commands[i], true
		}
	}
	return nil, false
}

func (d Document) Clone() Document {
	cloned := d
	if d.Servers != nil {
		cloned.Servers = make(map[string]Server, len(d.Servers))
		for name, server := range d.Servers {
			server.Variables = cloneStringMap(server.Variables)
			cloned.Servers[name] = server
		}
	}
	if d.Auth != nil {
		cloned.Auth = make(map[string]AuthScheme, len(d.Auth))
		for name, scheme := range d.Auth {
			scheme.Scopes = append([]string(nil), scheme.Scopes...)
			cloned.Auth[name] = scheme
		}
	}
	cloned.Commands = make([]Command, len(d.Commands))
	for index, command := range d.Commands {
		command.Path = append([]string(nil), command.Path...)
		command.Parameters = cloneParameters(command.Parameters)
		command.Auth = append([]string(nil), command.Auth...)
		command.Responses = append([]Response(nil), command.Responses...)
		if command.Body != nil {
			body := *command.Body
			body.Fields = cloneParameters(command.Body.Fields)
			body.Example = cloneValue(command.Body.Example)
			command.Body = &body
		}
		if command.Source != nil {
			source := *command.Source
			command.Source = &source
		}
		cloned.Commands[index] = command
	}
	if d.Import != nil {
		metadata := *d.Import
		metadata.Diagnostics = append([]Diagnostic(nil), d.Import.Diagnostics...)
		cloned.Import = &metadata
	}
	return cloned
}

func cloneParameters(parameters []Parameter) []Parameter {
	cloned := make([]Parameter, len(parameters))
	for index, parameter := range parameters {
		parameter.Default = cloneValue(parameter.Default)
		parameter.Example = cloneValue(parameter.Example)
		parameter.Enum = make([]any, len(parameter.Enum))
		for enumIndex, value := range parameter.Enum {
			parameter.Enum[enumIndex] = cloneValue(value)
		}
		if parameter.Explode != nil {
			value := *parameter.Explode
			parameter.Explode = &value
		}
		cloned[index] = parameter
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneValue(value any) any {
	return cloneValueDepth(value, 0)
}

func cloneValueDepth(value any, depth int) any {
	if depth > 128 {
		return value
	}
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, item := range typed {
			cloned[key] = cloneValueDepth(item, depth+1)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneValueDepth(item, depth+1)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}

func Slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var output strings.Builder
	dash := false
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			output.WriteRune(char)
			dash = false
			continue
		}
		if output.Len() > 0 && !dash {
			output.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(output.String(), "-")
}

func SlugID(value string) string {
	parts := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return r == '.' || r == '/' || r == ':' || r == ' ' })
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if slug := Slug(part); slug != "" {
			clean = append(clean, slug)
		}
	}
	return strings.Join(clean, ".")
}

func EnvName(parts ...string) string {
	joined := strings.Join(parts, "_")
	joined = regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(joined, "_")
	return strings.ToUpper(strings.Trim(joined, "_"))
}
