package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/therealsylva/anyapi/internal/model"
	"go.yaml.in/yaml/v3"
)

type File struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

type Profile struct {
	Server  string            `yaml:"server,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

func Path(api string) (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "anyapi", model.Slug(api)+".yaml"), nil
}

func Load(api string) (File, error) {
	path, err := Path(api)
	if err != nil {
		return File{}, err
	}
	// #nosec G304 -- path is derived from the OS config directory and a slugged API name.
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return File{Profiles: map[string]Profile{}}, nil
	}
	if err != nil {
		return File{}, fmt.Errorf("read profile configuration: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return File{}, fmt.Errorf("read profile configuration: %w", err)
	}
	if len(data) > 1<<20 {
		return File{}, errors.New("profile configuration exceeds 1 MiB limit")
	}
	return decode(data)
}

func decode(data []byte) (File, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var file File
	if err := decoder.Decode(&file); err != nil {
		return File{}, fmt.Errorf("decode profile configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return File{}, errors.New("profile configuration contains multiple YAML values")
		}
		return File{}, fmt.Errorf("decode trailing profile configuration: %w", err)
	}
	if file.Profiles == nil {
		file.Profiles = map[string]Profile{}
	}
	for profileName, profile := range file.Profiles {
		for header, value := range profile.Headers {
			if sensitiveHeader(header) {
				return File{}, fmt.Errorf("profile %q stores forbidden sensitive header %q; use the OS keyring or environment", profileName, header)
			}
			if strings.ContainsAny(value, "\r\n") {
				return File{}, fmt.Errorf("profile %q header %q contains a newline", profileName, header)
			}
		}
	}
	return file, nil
}

func sensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" {
		return true
	}
	for _, marker := range []string{"credential", "api-key", "api_key", "apikey", "access-key", "access_key", "token", "secret", "password", "passwd", "private-key", "private_key", "session"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
