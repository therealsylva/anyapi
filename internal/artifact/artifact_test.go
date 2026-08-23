package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/therealsylva/anyapi/internal/model"
)

func artifactDocument() *model.Document {
	document := &model.Document{Metadata: model.Metadata{Name: "artifact"}, Servers: map[string]model.Server{"production": {URL: "https://api.example.test"}}, DefaultServer: "production", Commands: []model.Command{{Path: []string{"ping"}, Operation: model.Operation{Method: "GET", Path: "/ping"}}}}
	document.Normalize()
	return document
}

func TestPackReadAndDeterminism(t *testing.T) {
	directory := t.TempDir()
	stub := filepath.Join(directory, "stub")
	if err := os.WriteFile(stub, []byte("native-stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(directory, "first")
	second := filepath.Join(directory, "second")
	info, err := Pack(stub, first, artifactDocument(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(stub, second, artifactDocument(), "test"); err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("artifact build is not deterministic")
	}
	loaded, err := Read(first, true)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PayloadSHA256 != info.PayloadSHA256 || loaded.Document.Metadata.Name != "artifact" {
		t.Fatalf("unexpected artifact info: %#v", loaded)
	}
}

func TestReadRejectsTamperedPayload(t *testing.T) {
	directory := t.TempDir()
	stub := filepath.Join(directory, "stub")
	output := filepath.Join(directory, "output")
	_ = os.WriteFile(stub, []byte("stub"), 0o755)
	if _, err := Pack(stub, output, artifactDocument(), "test"); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(output, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	stat, _ := file.Stat()
	if _, err := file.WriteAt([]byte{0xff}, stat.Size()-footerSize-1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err := Read(output, true); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
}

func TestReadRejectsValidlyEncodedInvalidDocument(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "invalid-artifact")
	payload, err := encode(Envelope{
		Format:      FormatVersion,
		ToolVersion: "test",
		Document: model.Document{
			APIVersion: model.APIVersion,
			Kind:       model.KindAPI,
			Metadata:   model.Metadata{Name: "invalid"},
			Commands:   []model.Command{{ID: "broken", Path: []string{"broken"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	metadata := footer{Magic: magic, FormatVersion: FormatVersion, Codec: CodecCBORZstd, PayloadSize: uint64(len(payload)), PayloadHash: digest}
	var encoded bytes.Buffer
	encoded.WriteString("stub")
	encoded.Write(payload)
	if err := binary.Write(&encoded, binary.BigEndian, metadata); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, true); err == nil {
		t.Fatal("artifact with an invalid embedded document was accepted")
	}
}

func TestReadRejectsNonzeroReservedFooter(t *testing.T) {
	directory := t.TempDir()
	stub := filepath.Join(directory, "stub")
	output := filepath.Join(directory, "output")
	if err := os.WriteFile(stub, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(stub, output, artifactDocument(), "test"); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(output, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{1}, stat.Size()-1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(output, true); err == nil {
		t.Fatal("artifact with nonzero reserved footer data was accepted")
	}
}

func TestPackRejectsUnresolvedImportErrors(t *testing.T) {
	directory := t.TempDir()
	stub := filepath.Join(directory, "stub")
	if err := os.WriteFile(stub, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	document := artifactDocument()
	document.Import = &model.ImportMetadata{
		Format: "openapi",
		Diagnostics: []model.Diagnostic{{
			Severity: model.SeverityError,
			Code:     "openapi.unresolved",
			Message:  "unresolved behavior",
		}},
	}
	if _, err := Pack(stub, filepath.Join(directory, "output"), document, "test"); err == nil {
		t.Fatal("artifact with an unresolved import error was accepted")
	}
}
