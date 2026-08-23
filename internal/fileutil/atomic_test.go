package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplacePublishesNewFile(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "document.anyapi")
	temporary := filepath.Join(directory, "document.tmp")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(temporary, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("destination contains %q", data)
	}
	if _, err := os.Stat(temporary); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists: %v", err)
	}
}

func TestReplaceRequiresSameDirectory(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	temporary := filepath.Join(first, "temporary")
	if err := os.WriteFile(temporary, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(temporary, filepath.Join(second, "destination")); err == nil {
		t.Fatal("expected cross-directory replacement to fail")
	}
}
