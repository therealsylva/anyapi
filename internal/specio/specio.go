package specio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/therealsylva/anyapi/internal/fileutil"
	"github.com/therealsylva/anyapi/internal/model"
	"go.yaml.in/yaml/v3"
)

const MaxDocumentSize = 32 << 20

func Decode(data []byte) (*model.Document, error) {
	if len(data) == 0 {
		return nil, errors.New("document is empty")
	}
	if len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("document exceeds %d byte limit", MaxDocumentSize)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var document model.Document
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode .anyapi document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("document contains multiple YAML values")
		}
		return nil, fmt.Errorf("decode trailing YAML: %w", err)
	}
	document.Normalize()
	return &document, nil
}

func Encode(document *model.Document) ([]byte, error) {
	if document == nil {
		return nil, errors.New("document is nil")
	}
	cloned := document.Clone()
	cloned.Normalize()
	data, err := yaml.Marshal(&cloned)
	if err != nil {
		return nil, fmt.Errorf("encode .anyapi document: %w", err)
	}
	if len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("encoded document exceeds %d byte limit", MaxDocumentSize)
	}
	return data, nil
}

func Read(path string) (*model.Document, error) {
	// #nosec G304 -- path is an explicit document path supplied by the CLI user.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxDocumentSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("%s exceeds %d byte limit", path, MaxDocumentSize)
	}
	document, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return document, nil
}

func Write(path string, document *model.Document) error {
	data, err := Encode(document)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".anyapi-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary document: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary document: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary document: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary document: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary document: %w", err)
	}
	if err := fileutil.Replace(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
