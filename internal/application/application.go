package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/therealsylva/anyapi/internal/artifact"
	"github.com/therealsylva/anyapi/internal/importer"
	"github.com/therealsylva/anyapi/internal/model"
	"github.com/therealsylva/anyapi/internal/specio"
	"github.com/therealsylva/anyapi/internal/target"
)

type Service struct {
	Version  string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	IsTTY    bool
	registry *importer.Registry
}

func New(version string, stdin io.Reader, stdout, stderr io.Writer, isTTY bool) *Service {
	return &Service{Version: version, Stdin: stdin, Stdout: stdout, Stderr: stderr, IsTTY: isTTY, registry: importer.NewRegistry()}
}

func (service *Service) Import(ctx context.Context, location, inline string, options importer.Options) (*importer.Result, error) {
	var source importer.Source
	var err error
	if inline != "" {
		source = importer.InlineSource(inline)
		if options.Format == "" || options.Format == "auto" {
			options.Format = "curl"
		}
	} else {
		source, err = importer.LoadSource(ctx, location, service.Stdin, options.AllowHTTP)
		if err != nil {
			return nil, err
		}
	}
	return service.registry.Import(ctx, source, options)
}

func (service *Service) Load(path string) (*model.Document, error) {
	if info, err := artifact.Read(path, true); err == nil {
		return info.Document, nil
	} else if !errors.Is(err, artifact.ErrNotArtifact) {
		return nil, fmt.Errorf("read compiled artifact: %w", err)
	}
	return specio.Read(path)
}

func (service *Service) Save(path string, document *model.Document, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; pass --force to replace it", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return specio.Write(path, document)
}

func (service *Service) Build(document *model.Document, outputPath, requestedTarget, runtimePath string, force bool) (*artifact.Info, error) {
	if outputPath == "" {
		outputPath = document.Metadata.Name
	}
	targetName, err := target.Parse(requestedTarget)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(targetName, "windows-") && !strings.HasSuffix(strings.ToLower(outputPath), ".exe") {
		outputPath += ".exe"
	}
	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			return nil, fmt.Errorf("%s already exists; pass --force to replace it", outputPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if runtimePath == "" {
		if targetName == target.Native() {
			runtimePath, err = os.Executable()
			if err != nil {
				return nil, err
			}
			runtimePath, err = filepath.EvalSymlinks(runtimePath)
			if err != nil {
				return nil, err
			}
		} else {
			runtimePath, err = target.RuntimePath(targetName)
			if err != nil {
				return nil, err
			}
			if _, err := os.Stat(runtimePath); err != nil {
				return nil, fmt.Errorf("target runtime %s is not installed; run anyapi targets install <binary>", targetName)
			}
		}
	}
	detected, err := target.Detect(runtimePath)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime: %w", err)
	}
	if detected != targetName {
		return nil, fmt.Errorf("runtime target is %s, requested %s", detected, targetName)
	}
	return artifact.Pack(runtimePath, outputPath, document, service.Version)
}

func (service *Service) NativeTarget() string { return runtime.GOOS + "-" + runtime.GOARCH }
