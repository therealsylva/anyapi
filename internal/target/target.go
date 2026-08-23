package target

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/therealsylva/anyapi/internal/artifact"
	"github.com/therealsylva/anyapi/internal/fileutil"
)

func Native() string { return runtime.GOOS + "-" + runtime.GOARCH }

func Parse(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "native" {
		return Native(), nil
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return "", fmt.Errorf("target must use os-arch form, such as linux-amd64")
	}
	validOS := map[string]bool{"linux": true, "darwin": true, "windows": true}
	validArch := map[string]bool{"amd64": true, "arm64": true}
	if !validOS[parts[0]] || !validArch[parts[1]] {
		return "", fmt.Errorf("unsupported target %q", value)
	}
	return value, nil
}

func CacheDir() (string, error) {
	directory, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "anyapi", "targets"), nil
}

func RuntimePath(target string) (string, error) {
	directory, err := CacheDir()
	if err != nil {
		return "", err
	}
	name := "runtime"
	if strings.HasPrefix(target, "windows-") {
		name += ".exe"
	}
	return filepath.Join(directory, target, name), nil
}

func Install(source, requestedTarget string) (string, error) {
	detected, err := Detect(source)
	if err != nil {
		return "", err
	}
	if _, err := artifact.Read(source, false); err == nil {
		return "", errors.New("compiled AnyAPI artifacts cannot be installed as runtime stubs; install a clean AnyAPI release binary")
	} else if !errors.Is(err, artifact.ErrNotArtifact) {
		return "", fmt.Errorf("inspect target runtime: %w", err)
	}
	if requestedTarget != "" {
		parsed, err := Parse(requestedTarget)
		if err != nil {
			return "", err
		}
		if parsed != detected {
			return "", fmt.Errorf("runtime is %s, not requested target %s", detected, parsed)
		}
	}
	destination, err := RuntimePath(detected)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", err
	}
	// #nosec G304 -- source is an explicit local runtime path supplied by the user.
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	stat, err := input.Stat()
	if err != nil {
		return "", err
	}
	if stat.Size() > 512<<20 {
		return "", errors.New("target runtime exceeds 512 MiB safety limit")
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".runtime-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, err := io.Copy(temporary, io.LimitReader(input, stat.Size()))
	if err != nil {
		_ = temporary.Close()
		return "", err
	}
	if written != stat.Size() {
		_ = temporary.Close()
		return "", fmt.Errorf("target runtime changed while installing: copied %d of %d bytes", written, stat.Size())
	}
	if err := temporary.Chmod(0o755); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := fileutil.Replace(temporaryPath, destination); err != nil {
		return "", err
	}
	return detected, nil
}

func List() ([]string, error) {
	directory, err := CacheDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		parsed, err := Parse(entry.Name())
		if err != nil || parsed != entry.Name() {
			continue
		}
		path, err := RuntimePath(entry.Name())
		if err == nil {
			if stat, err := os.Stat(path); err == nil && stat.Mode().IsRegular() {
				targets = append(targets, entry.Name())
			}
		}
	}
	sort.Strings(targets)
	return targets, nil
}

func Detect(path string) (string, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", errors.New("runtime is not a regular file")
	}
	if stat.Size() > 512<<20 {
		return "", errors.New("runtime exceeds 512 MiB safety limit")
	}
	if file, err := elf.Open(path); err == nil {
		defer file.Close()
		switch file.Machine {
		case elf.EM_X86_64:
			return "linux-amd64", nil
		case elf.EM_AARCH64:
			return "linux-arm64", nil
		}
		return "", fmt.Errorf("unsupported ELF architecture %v", file.Machine)
	}
	if file, err := macho.Open(path); err == nil {
		defer file.Close()
		switch file.Cpu {
		case macho.CpuAmd64:
			return "darwin-amd64", nil
		case macho.CpuArm64:
			return "darwin-arm64", nil
		}
		return "", fmt.Errorf("unsupported Mach-O architecture %v", file.Cpu)
	}
	if file, err := pe.Open(path); err == nil {
		defer file.Close()
		switch file.Machine {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			return "windows-amd64", nil
		case pe.IMAGE_FILE_MACHINE_ARM64:
			return "windows-arm64", nil
		}
		return "", fmt.Errorf("unsupported PE architecture %#x", file.Machine)
	}
	return "", errors.New("file is not a supported ELF, Mach-O, or PE executable")
}
