package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/therealsylva/anyapi/internal/apperr"
	"github.com/therealsylva/anyapi/internal/application"
	"github.com/therealsylva/anyapi/internal/artifact"
	"github.com/therealsylva/anyapi/internal/cli"
	"github.com/therealsylva/anyapi/internal/model"
	"github.com/therealsylva/anyapi/internal/runtimecli"
	"golang.org/x/term"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	isTTY := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if info, err := artifact.ReadSelf(); err == nil {
		root := runtimecli.New(info.Document, info.ToolVersion, runtimecli.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, IsTTY: isTTY})
		root.SetArgs(os.Args[1:])
		if err := root.Execute(); err != nil {
			fail(err)
		}
		return
	} else if !errors.Is(err, artifact.ErrNotArtifact) {
		fail(apperr.Wrap(apperr.ExitIntegrity, "integrity", "compiled AnyAPI payload is invalid: "+err.Error(), err))
		return
	}
	fullVersion := version
	if commit != "none" || date != "unknown" {
		fullVersion = fmt.Sprintf("%s (%s, %s)", version, commit, date)
	}
	service := application.New(fullVersion, os.Stdin, os.Stdout, os.Stderr, isTTY)
	root := cli.New(service)
	root.SetArgs(os.Args[1:])
	if err := root.Execute(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %s\n", model.CleanText(err.Error()))
	os.Exit(apperr.Code(err))
}
