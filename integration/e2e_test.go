package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGeneratedCLIEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess integration test in short mode")
	}

	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	builder := filepath.Join(temporary, "anyapi"+extension)
	generated := filepath.Join(temporary, "users"+extension)
	specification := filepath.Join(temporary, "users.anyapi")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run(t, ctx, repositoryRoot, "go", "build", "-trimpath", "-o", builder, "./cmd/anyapi")
	if exitCode, output := runExit(t, ctx, repositoryRoot, builder, "lint"); exitCode != 2 || !strings.Contains(output, "accepts 1 arg") {
		t.Fatalf("unexpected usage failure: exit=%d output=%s", exitCode, output)
	}

	type observedRequest struct {
		Method string
		Path   string
		Query  string
		Accept string
	}
	requests := make(chan observedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- observedRequest{
			Method: request.Method,
			Path:   request.URL.Path,
			Query:  request.URL.RawQuery,
			Accept: request.Header.Get("Accept"),
		}
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/users/missing" {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(writer, `{"error":"not found"}`)
			return
		}
		_, _ = fmt.Fprint(writer, `{"id":"usr_42","name":"Ada"}`)
	}))
	defer server.Close()

	curl := fmt.Sprintf("curl --header 'Accept: application/json' '%s/users/{id}?expand=profile'", server.URL)
	output := run(t, ctx, repositoryRoot, builder, "import", "--curl", curl, "--name", "users", "--output", specification)
	if !strings.Contains(output, "with 1 commands") {
		t.Fatalf("unexpected import output: %s", output)
	}
	run(t, ctx, repositoryRoot, builder, "lint", specification)
	run(t, ctx, repositoryRoot, builder, "build", specification, "--output", generated)
	run(t, ctx, repositoryRoot, builder, "verify", generated)
	if exitCode, output := runExit(t, ctx, repositoryRoot, generated, "does-not-exist"); exitCode != 2 || !strings.Contains(output, "unknown command") {
		t.Fatalf("unexpected generated CLI usage failure: exit=%d output=%s", exitCode, output)
	}

	output = run(t, ctx, repositoryRoot, generated, "users", "get", "usr_42", "--output", "json")
	var response map[string]string
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatalf("generated CLI emitted invalid JSON %q: %v", output, err)
	}
	if response["id"] != "usr_42" || response["name"] != "Ada" {
		t.Fatalf("unexpected generated CLI response: %#v", response)
	}

	select {
	case request := <-requests:
		if request.Method != http.MethodGet || request.Path != "/users/usr_42" || request.Query != "expand=profile" || request.Accept != "application/json" {
			t.Fatalf("unexpected request: %#v", request)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("generated CLI did not reach the test server")
	}

	about := run(t, ctx, repositoryRoot, generated, "about")
	if !strings.Contains(about, "users") || !strings.Contains(about, "Commands: 1") {
		t.Fatalf("unexpected about output: %s", about)
	}

	exitCode, failureOutput := runExit(t, ctx, repositoryRoot, generated, "users", "get", "missing", "--output", "json")
	if exitCode != 5 || !strings.Contains(failureOutput, `"not found"`) || !strings.Contains(failureOutput, "HTTP request failed") {
		t.Fatalf("unexpected HTTP failure: exit=%d output=%s", exitCode, failureOutput)
	}
}

func run(t *testing.T, ctx context.Context, directory, command string, arguments ...string) string {
	t.Helper()
	process := exec.CommandContext(ctx, command, arguments...)
	process.Dir = directory
	process.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", command, strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func runExit(t *testing.T, ctx context.Context, directory, command string, arguments ...string) (int, string) {
	t.Helper()
	process := exec.CommandContext(ctx, command, arguments...)
	process.Dir = directory
	process.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := process.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("%s %s failed without an exit status: %v\n%s", command, strings.Join(arguments, " "), err, output)
	}
	return exitError.ExitCode(), string(output)
}
