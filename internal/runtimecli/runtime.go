package runtimecli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/therealsylva/anyapi/internal/apperr"
	"github.com/therealsylva/anyapi/internal/credentials"
	"github.com/therealsylva/anyapi/internal/fileutil"
	"github.com/therealsylva/anyapi/internal/httpengine"
	"github.com/therealsylva/anyapi/internal/model"
	"github.com/therealsylva/anyapi/internal/output"
	"golang.org/x/term"
)

type IO struct {
	In    io.Reader
	Out   io.Writer
	Err   io.Writer
	IsTTY bool
}

type settings struct {
	server      string
	profile     string
	output      string
	outputFile  string
	headers     []string
	timeout     time.Duration
	retries     int
	maxResponse int64
	insecureTLS bool
	noAuth      bool
	dryRun      bool
	verbose     bool
}

func New(document *model.Document, version string, streams IO) *cobra.Command {
	if streams.In == nil {
		streams.In = os.Stdin
	}
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.Err == nil {
		streams.Err = os.Stderr
	}
	state := &settings{}
	root := &cobra.Command{
		Use:           document.Metadata.Name,
		Short:         document.Metadata.Description,
		Version:       firstNonEmpty(version, document.Metadata.Version),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          usageArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return apperr.Wrap(apperr.ExitUsage, "usage", err.Error(), err)
	})
	root.PersistentFlags().StringVar(&state.server, "server", "", "server name or absolute base URL")
	root.PersistentFlags().StringVar(&state.profile, "profile", "", "local configuration profile")
	root.PersistentFlags().StringVarP(&state.output, "output", "o", "auto", "output format: auto, raw, json, yaml, or table")
	root.PersistentFlags().StringVar(&state.outputFile, "output-file", "", "write the raw response body to a file")
	root.PersistentFlags().StringArrayVarP(&state.headers, "header", "H", nil, "additional request header (repeatable)")
	root.PersistentFlags().DurationVar(&state.timeout, "timeout", 30*time.Second, "request timeout")
	root.PersistentFlags().IntVar(&state.retries, "retries", 2, "retries for idempotent transient failures")
	root.PersistentFlags().Int64Var(&state.maxResponse, "max-response", 64<<20, "maximum response bytes held in memory")
	root.PersistentFlags().BoolVar(&state.insecureTLS, "insecure", false, "disable TLS certificate verification")
	root.PersistentFlags().BoolVar(&state.noAuth, "no-auth", false, "skip configured authentication")
	root.PersistentFlags().BoolVar(&state.dryRun, "dry-run", false, "print the redacted request without sending it")
	root.PersistentFlags().BoolVarP(&state.verbose, "verbose", "v", false, "print response status and timing to stderr")
	root.AddCommand(authCommand(document, streams))
	root.AddCommand(aboutCommand(document, version))
	installCommands(root, document, version, streams, state)
	return root
}

func installCommands(root *cobra.Command, document *model.Document, version string, streams IO, state *settings) {
	nodes := map[string]*cobra.Command{"": root}
	for index := range document.Commands {
		apiCommand := &document.Commands[index]
		for depth, segment := range apiCommand.Path {
			key := strings.Join(apiCommand.Path[:depth+1], " ")
			parentKey := strings.Join(apiCommand.Path[:depth], " ")
			parent := nodes[parentKey]
			node := nodes[key]
			if node == nil {
				node = &cobra.Command{Use: segment, SilenceUsage: true, SilenceErrors: true, Args: usageArgs(cobra.NoArgs)}
				parent.AddCommand(node)
				nodes[key] = node
			}
			if depth == len(apiCommand.Path)-1 {
				configureLeaf(node, document, apiCommand, version, streams, state)
			}
		}
	}
}

func configureLeaf(leaf *cobra.Command, document *model.Document, apiCommand *model.Command, version string, streams IO, state *settings) {
	leaf.Short = apiCommand.Summary
	leaf.Long = firstNonEmpty(apiCommand.Description, apiCommand.Summary)
	positionals := make([]model.Parameter, 0)
	valueBindings := map[string]*[]string{}
	bodyBindings := map[string]*[]string{}
	parameterFlags := map[string]string{}
	bodyFlags := map[string]string{}
	usedFlags := map[string]bool{
		"server": true, "profile": true, "output": true, "output-file": true,
		"header": true, "timeout": true, "retries": true, "max-response": true,
		"insecure": true, "no-auth": true, "dry-run": true, "verbose": true,
		"help": true, "version": true,
	}
	if apiCommand.Body != nil {
		usedFlags["body"] = true
		usedFlags["body-file"] = true
	}
	for _, parameter := range apiCommand.Parameters {
		parameter := parameter
		if parameter.Positional {
			positionals = append(positionals, parameter)
			if parameter.Required {
				leaf.Use += " <" + parameter.Name + ">"
			} else {
				leaf.Use += " [" + parameter.Name + "]"
			}
		}
		flag := availableFlag(firstNonEmpty(parameter.Flag, model.Slug(parameter.Name)), "parameter", usedFlags)
		values := []string(nil)
		valueBindings[parameter.Name] = &values
		parameterFlags[parameter.Name] = flag
		usedFlags[flag] = true
		leaf.Flags().StringArrayVar(valueBindings[parameter.Name], flag, nil, flagDescription(parameter))
	}
	if apiCommand.Body != nil {
		for _, field := range apiCommand.Body.Fields {
			field := field
			flag := availableFlag(firstNonEmpty(field.Flag, model.Slug(field.Name)), "body", usedFlags)
			usedFlags[flag] = true
			values := []string(nil)
			bodyBindings[field.Name] = &values
			bodyFlags[field.Name] = flag
			leaf.Flags().StringArrayVar(bodyBindings[field.Name], flag, nil, flagDescription(field))
		}
	}
	var rawBody string
	var bodyFile string
	if apiCommand.Body != nil {
		leaf.Flags().StringVar(&rawBody, "body", "", "literal request body")
		leaf.Flags().StringVar(&bodyFile, "body-file", "", "request body file, or - for stdin")
	}
	leaf.Args = func(_ *cobra.Command, args []string) error {
		if len(args) > len(positionals) {
			return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("expected at most %d positional arguments, received %d", len(positionals), len(args)))
		}
		return nil
	}
	leaf.RunE = func(leafCommand *cobra.Command, args []string) error {
		if !validOutputMode(state.output) {
			return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("unsupported output mode %q; use auto, raw, json, yaml, or table", state.output))
		}
		runtimeCommand := *apiCommand
		runtimeCommand.Parameters = append([]model.Parameter(nil), apiCommand.Parameters...)
		for index := range runtimeCommand.Parameters {
			if flag := parameterFlags[runtimeCommand.Parameters[index].Name]; flag != "" {
				runtimeCommand.Parameters[index].Flag = flag
			}
		}
		if apiCommand.Body != nil {
			body := *apiCommand.Body
			body.Fields = append([]model.Parameter(nil), apiCommand.Body.Fields...)
			for index := range body.Fields {
				if flag := bodyFlags[body.Fields[index].Name]; flag != "" {
					body.Fields[index].Flag = flag
				}
			}
			runtimeCommand.Body = &body
		}
		input := httpengine.Input{Values: map[string][]string{}, BodyValues: map[string][]string{}, Body: rawBody, BodyFile: bodyFile, Stdin: streams.In}
		for name, binding := range valueBindings {
			if len(*binding) > 0 {
				input.Values[name] = append([]string(nil), (*binding)...)
			}
		}
		for name, binding := range bodyBindings {
			if len(*binding) > 0 {
				input.BodyValues[name] = append([]string(nil), (*binding)...)
			}
		}
		for index, value := range args {
			parameter := positionals[index]
			if len(input.Values[parameter.Name]) > 0 {
				return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("%s was provided both positionally and with --%s", parameter.Name, parameterFlags[parameter.Name]))
			}
			input.Values[parameter.Name] = []string{value}
		}
		response, err := httpengine.Execute(leafCommand.Context(), document, &runtimeCommand, input, httpengine.Options{
			Server: state.server, Profile: state.profile, Headers: state.headers, Timeout: state.timeout,
			Retries: state.retries, MaxResponse: state.maxResponse, InsecureTLS: state.insecureTLS,
			NoAuth: state.noAuth, DryRun: state.dryRun, UserAgent: document.Metadata.Name + "/" + firstNonEmpty(document.Metadata.Version, version) + " anyapi-runtime/" + version,
		})
		if err != nil {
			return err
		}
		if response.DryRun {
			return output.Prepared(streams.Out, response.Prepared)
		}
		if state.outputFile != "" {
			if err := writeOutputFile(state.outputFile, response.Body, streams.Out); err != nil {
				return err
			}
		} else if err := output.Response(streams.Out, response.Body, response.Headers, state.output, streams.IsTTY); err != nil {
			return apperr.Wrap(apperr.ExitGeneral, "output", err.Error(), err)
		}
		if state.verbose {
			_, _ = fmt.Fprintf(streams.Err, "HTTP %s in %s\n", response.Status, response.Duration.Round(time.Millisecond))
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return apperr.New(apperr.ExitHTTP, "http", fmt.Sprintf("HTTP request failed with %s", response.Status))
		}
		return nil
	}
}

func validOutputMode(value string) bool {
	switch strings.ToLower(value) {
	case "", "auto", "raw", "json", "yaml", "table":
		return true
	default:
		return false
	}
}

func availableFlag(preferred, namespace string, used map[string]bool) string {
	if preferred == "" {
		preferred = namespace + "-value"
	}
	if !used[preferred] {
		return preferred
	}
	base := namespace + "-" + preferred
	if !used[base] {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s-%d", base, suffix)
		if !used[candidate] {
			return candidate
		}
	}
}

func authCommand(document *model.Document, streams IO) *cobra.Command {
	root := &cobra.Command{Use: "auth", Short: "Manage API credentials in the OS keyring", Args: usageArgs(cobra.NoArgs)}
	listCommand := &cobra.Command{
		Use: "list", Short: "List authentication schemes", Args: usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			keys := make([]string, 0, len(document.Auth))
			for name := range document.Auth {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			for _, name := range keys {
				scheme := document.Auth[name]
				status := "missing"
				if credentials.Available(document.Metadata.Name, name, scheme) {
					status = "available"
				}
				env := scheme.Env
				if strings.EqualFold(scheme.Type, "basic") {
					env = scheme.UsernameEnv + "," + scheme.PasswordEnv
				}
				_, _ = fmt.Fprintf(streams.Out, "%s\t%s\t%s\t%s\n", name, scheme.Type, status, env)
			}
			return nil
		},
	}
	var username string
	var secretStdin bool
	setCommand := &cobra.Command{
		Use: "set <scheme>", Short: "Store a credential in the OS keyring", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			scheme, ok := document.Auth[name]
			if !ok {
				return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("authentication scheme %q is undefined", name))
			}
			secret, err := readSecret(streams, secretStdin)
			if err != nil {
				return err
			}
			if err := credentials.Set(document.Metadata.Name, name, scheme, username, secret); err != nil {
				return apperr.Wrap(apperr.ExitAuth, "authentication", err.Error(), err)
			}
			_, _ = fmt.Fprintf(streams.Out, "Credential stored for %s.\n", name)
			return nil
		},
	}
	setCommand.Flags().StringVar(&username, "username", "", "username for basic authentication")
	setCommand.Flags().BoolVar(&secretStdin, "secret-stdin", false, "read the secret from stdin")
	deleteCommand := &cobra.Command{
		Use: "delete <scheme>", Short: "Delete a stored credential", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, ok := document.Auth[args[0]]; !ok {
				return apperr.New(apperr.ExitUsage, "usage", fmt.Sprintf("authentication scheme %q is undefined", args[0]))
			}
			if err := credentials.Delete(document.Metadata.Name, args[0]); err != nil {
				return apperr.Wrap(apperr.ExitAuth, "authentication", err.Error(), err)
			}
			_, _ = fmt.Fprintf(streams.Out, "Credential deleted for %s.\n", args[0])
			return nil
		},
	}
	root.AddCommand(listCommand, setCommand, deleteCommand)
	return root
}

func aboutCommand(document *model.Document, version string) *cobra.Command {
	return &cobra.Command{
		Use: "about", Short: "Show the embedded API manifest", Args: usageArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(command.OutOrStdout(), "%s %s\n%s\nCommands: %d\nGenerated by AnyAPI %s\n", document.Metadata.Name, document.Metadata.Version, document.Metadata.Description, len(document.Commands), version)
			return err
		},
	}
}

func readSecret(streams IO, fromStdin bool) (string, error) {
	if fromStdin {
		reader := bufio.NewReader(io.LimitReader(streams.In, 1<<20))
		value, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", apperr.Wrap(apperr.ExitAuth, "authentication", "read secret from stdin", err)
		}
		if len(value) >= 1<<20 {
			return "", apperr.New(apperr.ExitAuth, "authentication", "secret exceeds 1 MiB limit")
		}
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
		if value == "" {
			return "", apperr.New(apperr.ExitAuth, "authentication", "secret cannot be empty")
		}
		return value, nil
	}
	if file, ok := streams.In.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		_, _ = io.WriteString(streams.Err, "Secret: ")
		value, err := term.ReadPassword(int(file.Fd()))
		_, _ = io.WriteString(streams.Err, "\n")
		if err != nil {
			return "", apperr.Wrap(apperr.ExitAuth, "authentication", "read secret", err)
		}
		if len(value) == 0 {
			return "", apperr.New(apperr.ExitAuth, "authentication", "secret cannot be empty")
		}
		if len(value) > 1<<20 {
			return "", apperr.New(apperr.ExitAuth, "authentication", "secret exceeds 1 MiB limit")
		}
		return string(value), nil
	}
	return "", apperr.New(apperr.ExitUsage, "usage", "non-interactive input requires --secret-stdin")
}

func flagDescription(parameter model.Parameter) string {
	description := parameter.Description
	if description == "" {
		description = parameter.Name
	}
	if parameter.Required {
		description += " (required)"
	}
	if len(parameter.Enum) > 0 {
		description += fmt.Sprintf("; one of %v", parameter.Enum)
	}
	if parameter.Format == "binary" {
		description += "; file path"
	}
	return description
}

func writeOutputFile(path string, data []byte, stdout io.Writer) error {
	if path == "-" {
		_, err := stdout.Write(data)
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return apperr.Wrap(apperr.ExitGeneral, "output", "create output directory", err)
	}
	temporary, err := os.CreateTemp(directory, ".anyapi-response-*.tmp")
	if err != nil {
		return apperr.Wrap(apperr.ExitGeneral, "output", "create output file", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := fileutil.Replace(temporaryPath, path); err != nil {
		return err
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func usageArgs(validator cobra.PositionalArgs) cobra.PositionalArgs {
	return func(command *cobra.Command, args []string) error {
		if err := validator(command, args); err != nil {
			return apperr.Wrap(apperr.ExitUsage, "usage", err.Error(), err)
		}
		return nil
	}
}
