package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/therealsylva/anyapi/internal/application"
	"github.com/therealsylva/anyapi/internal/artifact"
	"github.com/therealsylva/anyapi/internal/banner"
	"github.com/therealsylva/anyapi/internal/importer"
	"github.com/therealsylva/anyapi/internal/model"
	"github.com/therealsylva/anyapi/internal/runtimecli"
	"github.com/therealsylva/anyapi/internal/shelllex"
)

type session struct {
	service  *application.Service
	document *model.Document
	path     string
	selected string
	dirty    bool
	undo     []model.Document
	redo     []model.Document
	line     *readline.Instance
}

func Run(ctx context.Context, service *application.Service) error {
	historyPath := ""
	if cache, err := os.UserCacheDir(); err == nil {
		directory := filepath.Join(cache, "anyapi")
		if os.MkdirAll(directory, 0o700) == nil {
			historyPath = filepath.Join(directory, "history")
			if stat, statErr := os.Stat(historyPath); statErr == nil && stat.Mode().IsRegular() {
				_ = os.Chmod(historyPath, 0o600)
			}
		}
	}
	completer := readline.NewPrefixCompleter(
		readline.PcItem("help"), readline.PcItem("import"), readline.PcItem("open"), readline.PcItem("save"),
		readline.PcItem("show", readline.PcItem("commands"), readline.PcItem("servers"), readline.PcItem("auth"), readline.PcItem("request")),
		readline.PcItem("use"), readline.PcItem("back"), readline.PcItem("set"), readline.PcItem("unset"),
		readline.PcItem("rename"), readline.PcItem("resolve"), readline.PcItem("lint"), readline.PcItem("run"),
		readline.PcItem("test"), readline.PcItem("build"), readline.PcItem("status"), readline.PcItem("undo"),
		readline.PcItem("redo"), readline.PcItem("clear"), readline.PcItem("exit"), readline.PcItem("quit"),
	)
	line, err := readline.NewEx(&readline.Config{
		Prompt:                 "anyapi > ",
		HistoryFile:            historyPath,
		HistoryLimit:           1000,
		DisableAutoSaveHistory: true,
		AutoComplete:           completer,
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
		Stdin:                  io.NopCloser(service.Stdin),
		Stdout:                 service.Stdout,
		Stderr:                 service.Stderr,
		FuncIsTerminal:         func() bool { return service.IsTTY },
	})
	if err != nil {
		return err
	}
	defer line.Close()
	state := &session{service: service, line: line}
	_, _ = fmt.Fprintln(service.Stdout, banner.Text())
	_, _ = fmt.Fprintf(service.Stdout, "\nAnyAPI Console %s\nLocal API-to-CLI compiler\nType help for commands.\n\n", model.CleanInline(service.Version))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line.SetPrompt(state.prompt())
		raw, err := line.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			_, _ = fmt.Fprintln(service.Stderr, "Cancelled.")
			continue
		}
		if errors.Is(err, io.EOF) {
			if state.dirty {
				if service.IsTTY {
					_, _ = fmt.Fprintln(service.Stderr, "Unsaved changes remain; use exit --force or save first.")
					continue
				}
				return errors.New("end of input reached with unsaved changes")
			}
			return nil
		}
		if err != nil {
			return err
		}
		tokens, err := shelllex.Split(raw)
		if err != nil {
			_, _ = fmt.Fprintf(service.Stderr, "error: %s\n", model.CleanText(err.Error()))
			continue
		}
		if len(tokens) == 0 {
			continue
		}
		if historySafe(tokens) {
			if err := line.SaveHistory(raw); err == nil && historyPath != "" {
				_ = os.Chmod(historyPath, 0o600)
			}
		}
		exit, err := state.execute(ctx, tokens)
		if err != nil {
			_, _ = fmt.Fprintf(service.Stderr, "error: %s\n", model.CleanText(err.Error()))
		}
		if exit {
			return nil
		}
	}
}

func (state *session) prompt() string {
	if state.document == nil {
		return "anyapi > "
	}
	name := state.document.Metadata.Name
	if state.selected != "" {
		name += "/" + state.selected
	}
	if state.dirty {
		name += "*"
	}
	return "anyapi(" + name + ") > "
}

func (state *session) execute(ctx context.Context, tokens []string) (bool, error) {
	command := strings.ToLower(tokens[0])
	args := tokens[1:]
	switch command {
	case "help", "?":
		state.help()
	case "import":
		return false, state.importSource(ctx, args)
	case "open":
		path, force, err := pathAndForce(args)
		if err != nil {
			return false, errors.New("usage: open <file.anyapi> [--force]")
		}
		if state.dirty && !force {
			return false, errors.New("unsaved changes remain; save first or use open --force")
		}
		documentPath := path
		var document *model.Document
		if info, artifactErr := artifact.Read(path, true); artifactErr == nil {
			document = info.Document
			documentPath = ""
		} else if !errors.Is(artifactErr, artifact.ErrNotArtifact) {
			return false, artifactErr
		} else {
			document, err = state.service.Load(path)
			if err != nil {
				return false, err
			}
		}
		state.document, state.path, state.selected, state.dirty = document, documentPath, "", false
		state.undo, state.redo = nil, nil
		_, _ = fmt.Fprintf(state.service.Stdout, "Opened %s with %d commands.\n", model.CleanInline(path), len(document.Commands))
	case "save":
		if state.document == nil {
			return false, errors.New("no document is loaded")
		}
		path, force, err := optionalPathAndForce(args, state.path)
		if err != nil {
			return false, errors.New("usage: save [file.anyapi] [--force]")
		}
		if path == "" {
			path = state.document.Metadata.Name + ".anyapi"
		}
		replaceCurrent := state.path != "" && samePath(path, state.path)
		if err := state.service.Save(path, state.document, force || replaceCurrent); err != nil {
			return false, err
		}
		state.path, state.dirty = path, false
		_, _ = fmt.Fprintf(state.service.Stdout, "Saved %s.\n", model.CleanInline(path))
	case "show":
		return false, state.show(args)
	case "use":
		if state.document == nil || len(args) == 0 {
			return false, errors.New("usage: use <command ID or path>")
		}
		needle := strings.Join(args, " ")
		selected, ok := state.document.Command(needle)
		if !ok {
			return false, fmt.Errorf("command %q does not exist", needle)
		}
		state.selected = selected.ID
	case "back":
		state.selected = ""
	case "rename":
		selected, err := state.selectedCommand()
		if err != nil {
			return false, err
		}
		if len(args) == 0 {
			return false, errors.New("usage: rename <new command path>")
		}
		state.snapshot()
		path := make([]string, 0, len(args))
		for _, arg := range args {
			if slug := model.Slug(arg); slug != "" {
				path = append(path, slug)
			}
		}
		if len(path) == 0 {
			state.restoreSnapshot()
			return false, errors.New("command path must contain at least one CLI identifier")
		}
		selected.Path = path
		selected.ID = strings.Join(path, ".")
		state.selected = selected.ID
		state.dirty = true
	case "set":
		return false, state.set(args)
	case "unset":
		return false, state.unset(args)
	case "resolve":
		return false, state.resolve(args)
	case "lint":
		if state.document == nil {
			return false, errors.New("no document is loaded")
		}
		diagnostics := state.document.AllDiagnostics()
		if len(diagnostics) == 0 {
			_, _ = fmt.Fprintln(state.service.Stdout, "No diagnostics.")
		} else {
			for _, diagnostic := range diagnostics {
				diagnostic = model.CleanDiagnostic(diagnostic)
				_, _ = fmt.Fprintf(state.service.Stdout, "%s %s %s: %s\n", strings.ToUpper(string(diagnostic.Severity)), diagnostic.Code, diagnostic.Path, diagnostic.Message)
			}
		}
	case "run", "test":
		return false, state.run(ctx, args, command == "test")
	case "build":
		return false, state.build(args)
	case "status":
		state.status()
	case "undo":
		return false, state.undoChange()
	case "redo":
		return false, state.redoChange()
	case "clear":
		_, _ = io.WriteString(state.service.Stdout, "\x1b[2J\x1b[H")
	case "exit", "quit":
		if len(args) > 1 || (len(args) == 1 && args[0] != "--force") {
			return false, errors.New("usage: exit [--force]")
		}
		force := len(args) == 1 && args[0] == "--force"
		if state.dirty && !force {
			return false, errors.New("unsaved changes remain; save first or use exit --force")
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown command %q; type help", command)
	}
	return false, nil
}

func (state *session) importSource(ctx context.Context, args []string) error {
	format := "auto"
	name := ""
	inline := ""
	location := ""
	force := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--format", "-f":
			index++
			if index >= len(args) {
				return errors.New("--format requires a value")
			}
			format = args[index]
		case "--name":
			index++
			if index >= len(args) {
				return errors.New("--name requires a value")
			}
			name = args[index]
		case "--curl":
			index++
			if index >= len(args) {
				return errors.New("--curl requires a quoted command")
			}
			inline = args[index]
		case "--allow-http":
			// Applied below after the complete command has been parsed.
		case "--force":
			force = true
		default:
			if location != "" {
				return errors.New("import accepts one source")
			}
			location = args[index]
		}
	}
	if location == "" && inline == "" {
		return errors.New("usage: import <source> [--format FORMAT], or import --curl 'curl ...'")
	}
	if state.dirty && !force {
		return errors.New("unsaved changes remain; save first or use import --force")
	}
	allowHTTP := false
	for _, arg := range args {
		if arg == "--allow-http" {
			allowHTTP = true
		}
	}
	result, err := state.service.Import(ctx, location, inline, importer.Options{Format: format, Name: name, AllowHTTP: allowHTTP})
	if err != nil {
		return err
	}
	state.document, state.path, state.selected, state.dirty = result.Document, "", "", true
	state.undo, state.redo = nil, nil
	_, _ = fmt.Fprintf(state.service.Stdout, "Imported %d commands with %d diagnostics.\n", len(result.Document.Commands), len(result.Diagnostics))
	return nil
}

func (state *session) show(args []string) error {
	if state.document == nil {
		return errors.New("no document is loaded")
	}
	section := "summary"
	if len(args) > 0 {
		section = strings.ToLower(args[0])
	}
	switch section {
	case "summary":
		state.status()
	case "commands":
		for _, command := range state.document.Commands {
			_, _ = fmt.Fprintf(state.service.Stdout, "%-28s %-32s %s %s\n", model.CleanInline(command.ID), model.CleanInline(strings.Join(command.Path, " ")), model.CleanInline(command.Operation.Method), model.CleanInline(command.Operation.Path))
		}
	case "servers":
		keys := make([]string, 0, len(state.document.Servers))
		for name := range state.document.Servers {
			keys = append(keys, name)
		}
		sortStrings(keys)
		for _, name := range keys {
			marker := " "
			if name == state.document.DefaultServer {
				marker = "*"
			}
			_, _ = fmt.Fprintf(state.service.Stdout, "%s %-20s %s\n", marker, name, safeServerURL(state.document.Servers[name].URL))
		}
	case "auth":
		keys := make([]string, 0, len(state.document.Auth))
		for name := range state.document.Auth {
			keys = append(keys, name)
		}
		sortStrings(keys)
		for _, name := range keys {
			scheme := state.document.Auth[name]
			_, _ = fmt.Fprintf(state.service.Stdout, "%-20s %-12s %s\n", model.CleanInline(name), model.CleanInline(scheme.Type), model.CleanInline(scheme.Env))
		}
	case "request":
		selected, err := state.selectedCommand()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(state.service.Stdout, "%s %s\nID: %s\nCLI: %s\n", selected.Operation.Method, selected.Operation.Path, selected.ID, strings.Join(selected.Path, " "))
		for _, parameter := range selected.Parameters {
			_, _ = fmt.Fprintf(state.service.Stdout, "  %-18s %-8s %-8s required=%t\n", parameter.Flag, parameter.In, parameter.Type, parameter.Required)
		}
	default:
		return fmt.Errorf("unknown show section %q", section)
	}
	return nil
}

func safeServerURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[invalid server URL]"
	}
	hadQuery := parsed.RawQuery != ""
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	result := parsed.String()
	if hadQuery {
		result += "?[redacted]"
	}
	return model.CleanText(result)
}

func (state *session) set(args []string) error {
	if state.document == nil || len(args) < 2 {
		return errors.New("usage: set <name|description|server|method|path|summary> <value>")
	}
	key := strings.ToLower(args[0])
	value := strings.Join(args[1:], " ")
	state.snapshot()
	switch key {
	case "name":
		name := model.Slug(value)
		if name == "" {
			state.restoreSnapshot()
			return errors.New("name must contain at least one CLI identifier")
		}
		state.document.Metadata.Name = name
	case "description":
		state.document.Metadata.Description = value
	case "server":
		if len(args) != 3 {
			state.restoreSnapshot()
			return errors.New("usage: set server <name> <URL>")
		}
		parsed, err := url.Parse(args[2])
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			state.restoreSnapshot()
			return errors.New("server must be an absolute credential-free HTTP(S) URL without a query or fragment")
		}
		name := model.Slug(args[1])
		if name == "" {
			state.restoreSnapshot()
			return errors.New("server name must contain at least one CLI identifier")
		}
		state.document.Servers[name] = model.Server{URL: args[2]}
		state.document.DefaultServer = name
	case "method", "path", "summary":
		selected, err := state.selectedCommand()
		if err != nil {
			state.restoreSnapshot()
			return err
		}
		switch key {
		case "method":
			selected.Operation.Method = strings.ToUpper(value)
		case "path":
			selected.Operation.Path = value
		case "summary":
			selected.Summary = value
		}
	default:
		state.restoreSnapshot()
		return fmt.Errorf("unknown setting %q", key)
	}
	state.document.Normalize()
	state.dirty = true
	return nil
}

func (state *session) unset(args []string) error {
	if state.document == nil || len(args) == 0 {
		return errors.New("usage: unset <description|server> [name]")
	}
	state.snapshot()
	switch strings.ToLower(args[0]) {
	case "description":
		state.document.Metadata.Description = ""
	case "server":
		if len(args) != 2 {
			state.restoreSnapshot()
			return errors.New("usage: unset server <name>")
		}
		delete(state.document.Servers, args[1])
		if state.document.DefaultServer == args[1] {
			state.document.DefaultServer = ""
		}
	default:
		state.restoreSnapshot()
		return fmt.Errorf("unknown unset target %q", args[0])
	}
	state.document.Normalize()
	state.dirty = true
	return nil
}

func (state *session) resolve(args []string) error {
	if state.document == nil {
		return errors.New("no document is loaded")
	}
	if len(args) == 0 {
		if state.document.Import == nil || len(state.document.Import.Diagnostics) == 0 {
			_, _ = fmt.Fprintln(state.service.Stdout, "No import diagnostics remain.")
			return nil
		}
		for _, diagnostic := range state.document.Import.Diagnostics {
			_, _ = fmt.Fprintf(state.service.Stdout, "%s %s: %s\n", strings.ToUpper(string(diagnostic.Severity)), diagnostic.Code, diagnostic.Message)
		}
		_, _ = fmt.Fprintln(state.service.Stdout, "For literal path identifiers: resolve <literal> <parameter-name>")
		return nil
	}
	if len(args) != 2 {
		return errors.New("usage: resolve <literal-path-segment> <parameter-name>")
	}
	selected, err := state.selectedCommand()
	if err != nil {
		return err
	}
	literal := args[0]
	name := model.Slug(args[1])
	if name == "" {
		return errors.New("parameter name must contain at least one CLI identifier")
	}
	segments := strings.Split(selected.Operation.Path, "/")
	found := false
	for index, segment := range segments {
		if segment == literal {
			segments[index] = "{" + name + "}"
			found = true
		}
	}
	if !found {
		return fmt.Errorf("literal segment %q is not present in %s", literal, selected.Operation.Path)
	}
	state.snapshot()
	selected.Operation.Path = strings.Join(segments, "/")
	selected.Parameters = append(selected.Parameters, model.Parameter{Name: name, Flag: name, In: "path", Type: "string", Required: true, Positional: true, Example: literal})
	state.dirty = true
	return nil
}

func (state *session) run(ctx context.Context, args []string, dryRun bool) error {
	if state.document == nil {
		return errors.New("no document is loaded")
	}
	if state.document.HasErrors() {
		return errors.New("document validation failed; run lint for details")
	}
	runtimeArgs := append([]string(nil), args...)
	if state.selected != "" {
		selected, _ := state.document.Command(state.selected)
		runtimeArgs = append(append([]string(nil), selected.Path...), runtimeArgs...)
	}
	if dryRun {
		runtimeArgs = append(runtimeArgs, "--dry-run")
	}
	root := runtimecli.New(state.document, state.service.Version, runtimecli.IO{In: state.service.Stdin, Out: state.service.Stdout, Err: state.service.Stderr, IsTTY: state.service.IsTTY})
	root.SetArgs(runtimeArgs)
	return root.ExecuteContext(ctx)
}

func (state *session) build(args []string) error {
	if state.document == nil {
		return errors.New("no document is loaded")
	}
	if state.document.HasErrors() {
		return errors.New("document validation failed; run lint for details")
	}
	output := state.document.Metadata.Name
	target := "native"
	runtimePath := ""
	force := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "-o", "--output":
			index++
			if index >= len(args) {
				return errors.New("--output requires a value")
			}
			output = args[index]
		case "--target":
			index++
			if index >= len(args) {
				return errors.New("--target requires a value")
			}
			target = args[index]
		case "--runtime":
			index++
			if index >= len(args) {
				return errors.New("--runtime requires a value")
			}
			runtimePath = args[index]
		case "--force":
			force = true
		default:
			return fmt.Errorf("unknown build option %q", args[index])
		}
	}
	info, err := state.service.Build(state.document, output, target, runtimePath, force)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(state.service.Stdout, "Built %s with %d commands (sha256:%s).\n", model.CleanInline(info.OutputPath), len(state.document.Commands), info.PayloadSHA256)
	return nil
}

func (state *session) status() {
	if state.document == nil {
		_, _ = fmt.Fprintln(state.service.Stdout, "No document loaded.")
		return
	}
	_, _ = fmt.Fprintf(state.service.Stdout, "Name: %s\nPath: %s\nCommands: %d\nServers: %d\nSelected: %s\nModified: %t\n", model.CleanInline(state.document.Metadata.Name), model.CleanInline(firstNonEmpty(state.path, "[unsaved]")), len(state.document.Commands), len(state.document.Servers), model.CleanInline(firstNonEmpty(state.selected, "[none]")), state.dirty)
}

func (state *session) selectedCommand() (*model.Command, error) {
	if state.document == nil || state.selected == "" {
		return nil, errors.New("select a command first with use <command>")
	}
	command, ok := state.document.Command(state.selected)
	if !ok {
		return nil, errors.New("selected command no longer exists")
	}
	return command, nil
}

func (state *session) snapshot() {
	if state.document != nil {
		state.undo = append(state.undo, state.document.Clone())
		if len(state.undo) > 100 {
			state.undo = state.undo[len(state.undo)-100:]
		}
		state.redo = nil
	}
}

func (state *session) restoreSnapshot() {
	if len(state.undo) == 0 {
		return
	}
	state.document = &state.undo[len(state.undo)-1]
	state.undo = state.undo[:len(state.undo)-1]
}

func (state *session) undoChange() error {
	if state.document == nil || len(state.undo) == 0 {
		return errors.New("nothing to undo")
	}
	state.redo = append(state.redo, state.document.Clone())
	previous := state.undo[len(state.undo)-1]
	state.undo = state.undo[:len(state.undo)-1]
	state.document = &previous
	state.selected = ""
	state.dirty = true
	return nil
}

func (state *session) redoChange() error {
	if state.document == nil || len(state.redo) == 0 {
		return errors.New("nothing to redo")
	}
	state.undo = append(state.undo, state.document.Clone())
	next := state.redo[len(state.redo)-1]
	state.redo = state.redo[:len(state.redo)-1]
	state.document = &next
	state.selected = ""
	state.dirty = true
	return nil
}

func (state *session) help() {
	_, _ = fmt.Fprintln(state.service.Stdout, `Commands:
  import <source>                 Import cURL, OpenAPI, Swagger, or Postman
  open <file> [--force]           Open a document or compiled artifact
  save [file.anyapi] [--force]    Atomically save the current document
  show [summary|commands|servers|auth|request]
  use <command ID or path>        Enter command context
  back                            Leave command context
  set <field> <value>             Edit metadata, server, or selected operation
  unset <field> [name]            Remove an editable value
  rename <command path>           Rename the selected generated command
  resolve [literal parameter]     Review or resolve import ambiguity
  lint                            Validate the current document
  run [command and flags]         Execute through the generated runtime
  test [command and flags]        Preview a redacted request
  build [-o path] [--target t]    Build a standalone executable
  status                          Show console state
  undo | redo                     Navigate document edits
  clear                           Clear the terminal
  exit [--force]                  Close the console`)
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
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

func historySafe(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	switch strings.ToLower(tokens[0]) {
	case "run", "test", "import", "set":
		return false
	}
	lower := strings.ToLower(strings.Join(tokens, " "))
	for _, marker := range []string{"authorization", "credential", "api-key", "api_key", "apikey", "access-token", "access_token", "secret", "token", "password", "passwd", "private-key", "private_key", "cookie", "session", "--body", "--header"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func pathAndForce(args []string) (string, bool, error) {
	path, force, err := optionalPathAndForce(args, "")
	if err != nil || path == "" {
		return "", false, errors.New("path is required")
	}
	return path, force, nil
}

func optionalPathAndForce(args []string, fallback string) (string, bool, error) {
	path := fallback
	force := false
	pathSet := false
	for _, arg := range args {
		if arg == "--force" {
			force = true
			continue
		}
		if strings.HasPrefix(arg, "-") || pathSet {
			return "", false, errors.New("unexpected argument")
		}
		path = arg
		pathSet = true
	}
	return path, force, nil
}

func samePath(first, second string) bool {
	firstAbsolute, firstErr := filepath.Abs(first)
	secondAbsolute, secondErr := filepath.Abs(second)
	if firstErr == nil && secondErr == nil {
		return filepath.Clean(firstAbsolute) == filepath.Clean(secondAbsolute)
	}
	return filepath.Clean(first) == filepath.Clean(second)
}
