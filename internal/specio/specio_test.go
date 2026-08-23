package specio

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/therealsylva/anyapi/internal/model"
)

func TestRoundTripAndAtomicWrite(t *testing.T) {
	document := &model.Document{Metadata: model.Metadata{Name: "roundtrip"}, Servers: map[string]model.Server{"production": {URL: "https://api.example.test"}}, DefaultServer: "production", Commands: []model.Command{{Path: []string{"ping"}, Operation: model.Operation{Method: "GET", Path: "/ping"}}}}
	document.Normalize()
	path := filepath.Join(t.TempDir(), "api.anyapi")
	if err := Write(path, document); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Metadata.Name != document.Metadata.Name || len(loaded.Commands) != 1 {
		t.Fatalf("unexpected round trip: %#v", loaded)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows exposes only its read-only bit through os.FileMode; access is
	// enforced by the file's inherited ACL rather than Unix permission bits.
	if runtime.GOOS != "windows" && stat.Mode().Perm()&0o077 != 0 {
		t.Fatalf("document permissions are too broad: %o", stat.Mode().Perm())
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode([]byte("apiVersion: anyapi.dev/v1alpha1\nkind: API\nmetadata:\n  name: x\nunknown: true\ncommands: []\n"))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("apiVersion: anyapi.dev/v1alpha1\nkind: API\nmetadata: {name: fuzz}\ncommands: []\n"))
	f.Add([]byte("not: [valid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		document, err := Decode(data)
		if err == nil {
			_ = document.Validate()
		}
	})
}
