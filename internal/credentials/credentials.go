package credentials

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/therealsylva/anyapi/internal/model"
	"github.com/zalando/go-keyring"
)

var ErrMissing = errors.New("credential is unavailable")

var (
	keyringGet    = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

func service(api string) string { return "anyapi/" + model.Slug(api) }

func Resolve(api, schemeName string, scheme model.AuthScheme) (string, error) {
	if scheme.Env != "" {
		if value := os.Getenv(scheme.Env); value != "" {
			if err := validateSecret(value); err != nil {
				return "", err
			}
			return value, nil
		}
	}
	value, err := keyringGet(service(api), schemeName)
	if err == nil && value != "" {
		if validationErr := validateSecret(value); validationErr != nil {
			return "", validationErr
		}
		return value, nil
	}
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return "", fmt.Errorf("read credential from OS keyring: %w", err)
	}
	if scheme.Env != "" {
		return "", fmt.Errorf("%w: set %s or run %s auth set %s", ErrMissing, scheme.Env, api, schemeName)
	}
	return "", fmt.Errorf("%w: run %s auth set %s", ErrMissing, api, schemeName)
}

func ResolveBasic(api, schemeName string, scheme model.AuthScheme) (string, string, error) {
	username := ""
	password := ""
	if scheme.UsernameEnv != "" {
		username = os.Getenv(scheme.UsernameEnv)
	}
	if scheme.PasswordEnv != "" {
		password = os.Getenv(scheme.PasswordEnv)
	}
	if username != "" && password != "" {
		if err := validateBasic(username, password); err != nil {
			return "", "", err
		}
		return username, password, nil
	}
	stored, err := keyringGet(service(api), schemeName)
	if err == nil {
		storedUsername, storedPassword, _ := strings.Cut(stored, "\x00")
		if username == "" {
			username = storedUsername
		}
		if password == "" {
			password = storedPassword
		}
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return "", "", fmt.Errorf("read credential from OS keyring: %w", err)
	}
	if username == "" || password == "" {
		if scheme.UsernameEnv != "" && scheme.PasswordEnv != "" {
			return "", "", fmt.Errorf("%w: set %s and %s or run %s auth set %s", ErrMissing, scheme.UsernameEnv, scheme.PasswordEnv, api, schemeName)
		}
		return "", "", fmt.Errorf("%w: run %s auth set %s", ErrMissing, api, schemeName)
	}
	if err := validateBasic(username, password); err != nil {
		return "", "", err
	}
	return username, password, nil
}

func Set(api, schemeName string, scheme model.AuthScheme, username, secret string) error {
	if secret == "" {
		return errors.New("credential cannot be empty")
	}
	if err := validateSecret(secret); err != nil {
		return err
	}
	if strings.ContainsRune(secret, '\x00') || strings.ContainsRune(username, '\x00') {
		return errors.New("credentials cannot contain NUL bytes")
	}
	value := secret
	if strings.EqualFold(scheme.Type, "basic") {
		if username == "" {
			return errors.New("username cannot be empty for basic authentication")
		}
		if err := validateBasic(username, secret); err != nil {
			return err
		}
		value = username + "\x00" + secret
	}
	if err := keyringSet(service(api), schemeName, value); err != nil {
		return fmt.Errorf("store credential in OS keyring: %w", err)
	}
	return nil
}

func validateBasic(username, password string) error {
	if strings.ContainsRune(username, ':') {
		return errors.New("basic-auth username cannot contain a colon")
	}
	if err := validateSecret(username); err != nil {
		return errors.New("basic-auth username cannot contain control characters")
	}
	if err := validateSecret(password); err != nil {
		return errors.New("basic-auth password cannot contain control characters")
	}
	return nil
}

func validateSecret(value string) error {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return errors.New("credential cannot contain control characters")
		}
	}
	return nil
}

func Delete(api, schemeName string) error {
	err := keyringDelete(service(api), schemeName)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("delete credential from OS keyring: %w", err)
	}
	return nil
}

func Available(api, schemeName string, scheme model.AuthScheme) bool {
	if strings.EqualFold(scheme.Type, "basic") {
		if scheme.UsernameEnv != "" && scheme.PasswordEnv != "" && os.Getenv(scheme.UsernameEnv) != "" && os.Getenv(scheme.PasswordEnv) != "" {
			return true
		}
	} else if scheme.Env != "" && os.Getenv(scheme.Env) != "" {
		return true
	}
	value, err := keyringGet(service(api), schemeName)
	return err == nil && value != ""
}
