package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/therealsylva/anyapi/internal/apperr"
	"github.com/therealsylva/anyapi/internal/application"
	"github.com/therealsylva/anyapi/internal/artifact"
	"github.com/therealsylva/anyapi/internal/config"
	"github.com/therealsylva/anyapi/internal/console"
	"github.com/therealsylva/anyapi/internal/importer"
	"github.com/therealsylva/anyapi/internal/model"
	"github.com/therealsylva/anyapi/internal/runtimecli"
	"github.com/therealsylva/anyapi/internal/target"
	anyschema "github.com/therealsylva/anyapi/schema"
)

func New(service *application.Service) *cobra.Command {
	root := &cobra.Command{
		Use:           "anyapi",
		Short:         "Compile API specifications into standalone native CLIs",
		Long:          "AnyAPI imports cURL, OpenAPI, Swagger, and Postman definitions into an editable .anyapi document, executes it locally, and packages it as a standalone native command-line application.",
		Version:       service.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          usageArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			if service.IsTTY {
				return console.Run(command.Context(), service)
			}
			return command.Help()
		},
	}
	root.SetIn(service.Stdin)
	root.SetOut(service.Stdout)
	root.SetErr(service.Stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return apperr.Wrap(apperr.ExitUsage, "usage", err.Error(), err)
	})
	root.AddCommand(importCommand(service))
	root.AddCommand(lintCommand(service))
	root.AddCommand(inspectCommand(service))
	root.AddCommand(runCommand(service))
	root.AddCommand(buildCommand(service))
	root.AddCommand(verifyCommand(service))
	root.AddCommand(consoleCommand(service))
	root.AddCommand(targetsCommand(service))
	root.AddCommand(schemaCommand())
	root.AddCommand(doctorCommand(service))
	return root
}

func importCommand(service *application.Service) *cobra.Command {
	var format string
	var name string
	var outputPath string
	var inlineCurl string
	var allowHTTP bool
	var force bool
	command := &cobra.Command{
		Use:     "import [source]",
		Aliases: []string{"convert"},
		Short:   "Import cURL, OpenAPI, Swagger, or Postman",
		Args:    usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			location := ""
			if len(args) > 0 {
				location = args[0]
			}
			if inlineCurl == "" && location == "" {
				return apperr.New(apperr.ExitUsage, "usage", "provide a source path, URL, -, or --curl")
			}
			if inlineCurl != "" && location != "" {
				return apperr.New(apperr.ExitUsage, "usage", "source and --curl are mutually exclusive")
			}
			result, err := service.Import(command.Context(), location, inlineCurl, importer.Options{Format: format, Name: name, AllowHTTP: allowHTTP})
			if err != nil {
				return err
			}
			printDiagnostics(service.Stderr, result.Diagnostics)
			if outputPath == "" {
				outputPath = result.Document.Metadata.Name + ".anyapi"
			}
			if err := service.Save(outputPath, result.Document, force); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(service.Stdout, "Wrote %s with %d commands.\n", model.CleanInline(outputPath), len(result.Document.Commands))
			return nil
		},
	}
	command.Flags().StringVarP(&format, "format", "f", "auto", "source format: auto, curl, openapi, or postman")
	command.Flags().StringVar(&name, "name", "", "generated CLI name")
	command.Flags().StringVarP(&outputPath, "output", "o", "", "output .anyapi path")
	command.Flags().StringVar(&inlineCurl, "curl", "", "inline cURL command")
	command.Flags().BoolVar(&allowHTTP, "allow-http", false, "allow downloading a source over unencrypted HTTP")
	command.Flags().BoolVar(&force, "force", false, "replace an existing output file")
	return command
}

func lintCommand(service *application.Service) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use: "lint <file.anyapi>", Short: "Validate an AnyAPI document", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			document, err := service.Load(args[0])
			if err != nil {
				return err
			}
			diagnostics := document.AllDiagnostics()
			if jsonOutput {
				encoder := json.NewEncoder(service.Stdout)
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(diagnostics); err != nil {
					return err
				}
			} else if len(diagnostics) == 0 {
				_, _ = fmt.Fprintln(service.Stdout, "No diagnostics.")
			} else {
				printDiagnostics(service.Stdout, diagnostics)
			}
			for _, diagnostic := range diagnostics {
				if diagnostic.Severity == model.SeverityError {
					return apperr.New(apperr.ExitValidation, "validation", "document validation failed")
				}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit diagnostics as JSON")
	return command
}

func inspectCommand(service *application.Service) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use: "inspect <file>", Short: "Inspect an AnyAPI document or compiled binary", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			if info, err := artifact.Read(args[0], true); err == nil {
				if jsonOutput {
					return writeJSON(service.Stdout, map[string]any{"type": "artifact", "formatVersion": info.FormatVersion, "codec": "cbor+zstd", "payloadBytes": info.PayloadSize, "sha256": info.PayloadSHA256, "toolVersion": info.ToolVersion, "document": info.Document})
				}
				printDocumentSummary(service.Stdout, info.Document)
				_, _ = fmt.Fprintf(service.Stdout, "Artifact: format=%d codec=cbor+zstd payload=%d sha256=%s\n", info.FormatVersion, info.PayloadSize, info.PayloadSHA256)
				return nil
			} else if !errors.Is(err, artifact.ErrNotArtifact) {
				return apperr.Wrap(apperr.ExitIntegrity, "integrity", err.Error(), err)
			}
			document, err := service.Load(args[0])
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(service.Stdout, document)
			}
			printDocumentSummary(service.Stdout, document)
			return nil
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return command
}

func runCommand(service *application.Service) *cobra.Command {
	return &cobra.Command{
		Use: "run <file.anyapi> [command...]", Short: "Run a generated command without building", DisableFlagParsing: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				return command.Help()
			}
			if len(args) == 0 {
				return apperr.New(apperr.ExitUsage, "usage", "run requires a .anyapi document")
			}
			document, err := service.Load(args[0])
			if err != nil {
				return err
			}
			if diagnostics := document.AllDiagnostics(); hasDiagnosticErrors(diagnostics) {
				printDiagnostics(service.Stderr, diagnostics)
				return apperr.New(apperr.ExitValidation, "validation", "document validation failed")
			}
			runtimeRoot := runtimecli.New(document, service.Version, runtimecli.IO{In: service.Stdin, Out: service.Stdout, Err: service.Stderr, IsTTY: service.IsTTY})
			runtimeRoot.SetArgs(args[1:])
			return runtimeRoot.ExecuteContext(command.Context())
		},
	}
}

func buildCommand(service *application.Service) *cobra.Command {
	var outputPath string
	var targetName string
	var runtimePath string
	var force bool
	command := &cobra.Command{
		Use: "build <file.anyapi>", Short: "Build a standalone native CLI", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			document, err := service.Load(args[0])
			if err != nil {
				return err
			}
			if diagnostics := document.AllDiagnostics(); hasDiagnosticErrors(diagnostics) {
				printDiagnostics(service.Stderr, diagnostics)
				return apperr.New(apperr.ExitValidation, "validation", "document validation failed")
			}
			if outputPath == "" {
				outputPath = document.Metadata.Name
			}
			info, err := service.Build(document, outputPath, targetName, runtimePath, force)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(service.Stdout, "Built %s (%d-byte payload, sha256:%s).\n", model.CleanInline(info.OutputPath), info.PayloadSize, info.PayloadSHA256)
			return nil
		},
	}
	command.Flags().StringVarP(&outputPath, "output", "o", "", "output executable path")
	command.Flags().StringVar(&targetName, "target", "native", "target OS and architecture")
	command.Flags().StringVar(&runtimePath, "runtime", "", "explicit target runtime stub")
	command.Flags().BoolVar(&force, "force", false, "replace an existing output executable")
	return command
}

func verifyCommand(service *application.Service) *cobra.Command {
	return &cobra.Command{
		Use: "verify <binary>", Short: "Verify a compiled CLI payload and checksum", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			info, err := artifact.Read(args[0], true)
			if err != nil {
				return apperr.Wrap(apperr.ExitIntegrity, "integrity", err.Error(), err)
			}
			_, _ = fmt.Fprintf(service.Stdout, "Verified %s: %s %s, %d commands, sha256:%s.\n", model.CleanInline(args[0]), info.Document.Metadata.Name, info.Document.Metadata.Version, len(info.Document.Commands), info.PayloadSHA256)
			return nil
		},
	}
}

func consoleCommand(service *application.Service) *cobra.Command {
	return &cobra.Command{
		Use: "console", Aliases: []string{"shell"}, Short: "Open the interactive AnyAPI console", Args: usageArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error { return console.Run(command.Context(), service) },
	}
}

func targetsCommand(service *application.Service) *cobra.Command {
	root := &cobra.Command{Use: "targets", Short: "Manage offline cross-platform runtime stubs", Args: usageArgs(cobra.NoArgs)}
	root.AddCommand(&cobra.Command{
		Use: "list", Short: "List installed target runtimes", Args: usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			installed, err := target.List()
			if err != nil {
				return err
			}
			set := map[string]bool{target.Native(): true}
			for _, name := range installed {
				set[name] = true
			}
			names := make([]string, 0, len(set))
			for name := range set {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				suffix := "installed"
				if name == target.Native() {
					suffix = "native"
				}
				_, _ = fmt.Fprintf(service.Stdout, "%s\t%s\n", name, suffix)
			}
			return nil
		},
	})
	var requested string
	install := &cobra.Command{
		Use: "install <anyapi-binary>", Short: "Install a target runtime from an AnyAPI executable", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			detected, err := target.Install(args[0], requested)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(service.Stdout, "Installed runtime for %s.\n", detected)
			return nil
		},
	}
	install.Flags().StringVar(&requested, "target", "", "expected os-arch target")
	root.AddCommand(install)
	return root
}

func schemaCommand() *cobra.Command {
	return &cobra.Command{
		Use: "schema", Short: "Print the AnyAPI v1 JSON Schema", Args: usageArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := command.OutOrStdout().Write(anyschema.JSON)
			return err
		},
	}
}

func doctorCommand(service *application.Service) *cobra.Command {
	return &cobra.Command{
		Use: "doctor", Short: "Check the local AnyAPI environment", Args: usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			profilePath, profileErr := config.Path("api-name")
			cachePath, cacheErr := target.CacheDir()
			if profileErr != nil {
				profilePath = "unavailable: " + profileErr.Error()
			}
			if cacheErr != nil {
				cachePath = "unavailable: " + cacheErr.Error()
			}
			_, _ = fmt.Fprintf(service.Stdout, "Version: %s\nRuntime: %s/%s\nNative target: %s\nExecutable: %s\nProfile pattern: %s\nTarget cache: %s\n", model.CleanInline(service.Version), runtime.GOOS, runtime.GOARCH, target.Native(), model.CleanInline(executable), model.CleanInline(profilePath), model.CleanInline(cachePath))
			return nil
		},
	}
}

func printDiagnostics(writer io.Writer, diagnostics []model.Diagnostic) {
	for _, diagnostic := range diagnostics {
		diagnostic = model.CleanDiagnostic(diagnostic)
		location := ""
		if diagnostic.Path != "" {
			location = " " + diagnostic.Path
		}
		_, _ = fmt.Fprintf(writer, "%s %s%s: %s", strings.ToUpper(string(diagnostic.Severity)), diagnostic.Code, location, diagnostic.Message)
		if diagnostic.Hint != "" {
			_, _ = fmt.Fprintf(writer, " (%s)", diagnostic.Hint)
		}
		_, _ = fmt.Fprintln(writer)
	}
}

func hasDiagnosticErrors(diagnostics []model.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == model.SeverityError {
			return true
		}
	}
	return false
}

func printDocumentSummary(writer io.Writer, document *model.Document) {
	_, _ = fmt.Fprintf(writer, "Name: %s\nVersion: %s\nDescription: %s\nServers: %d\nAuthentication schemes: %d\nCommands: %d\n", document.Metadata.Name, document.Metadata.Version, document.Metadata.Description, len(document.Servers), len(document.Auth), len(document.Commands))
	for _, command := range document.Commands {
		_, _ = fmt.Fprintf(writer, "  %-28s %s %s\n", strings.Join(command.Path, " "), command.Operation.Method, command.Operation.Path)
	}
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func usageArgs(validator cobra.PositionalArgs) cobra.PositionalArgs {
	return func(command *cobra.Command, args []string) error {
		if err := validator(command, args); err != nil {
			return apperr.Wrap(apperr.ExitUsage, "usage", err.Error(), err)
		}
		return nil
	}
}
