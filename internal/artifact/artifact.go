package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/klauspost/compress/zstd"
	"github.com/therealsylva/anyapi/internal/fileutil"
	"github.com/therealsylva/anyapi/internal/model"
)

const (
	FormatVersion = uint16(1)
	CodecCBORZstd = uint16(1)
	footerSize    = 64
	maxPayload    = 64 << 20
	maxDocument   = 128 << 20
)

var magic = [8]byte{'A', 'N', 'Y', 'A', 'P', 'I', 0, 1}

type Envelope struct {
	Format      uint16         `cbor:"format"`
	ToolVersion string         `cbor:"toolVersion"`
	Document    model.Document `cbor:"document"`
}

type Info struct {
	FormatVersion uint16
	Codec         uint16
	PayloadSize   uint64
	PayloadSHA256 string
	ToolVersion   string
	Document      *model.Document
	OutputPath    string
}

type footer struct {
	Magic         [8]byte
	FormatVersion uint16
	Codec         uint16
	PayloadSize   uint64
	PayloadHash   [32]byte
	Reserved      [12]byte
}

func Pack(stubPath, outputPath string, document *model.Document, toolVersion string) (*Info, error) {
	if document == nil {
		return nil, errors.New("document is nil")
	}
	copyDocument := document.Clone()
	copyDocument.Normalize()
	for _, diagnostic := range copyDocument.AllDiagnostics() {
		if diagnostic.Severity == model.SeverityError {
			return nil, fmt.Errorf("document is invalid: %s: %s", diagnostic.Path, diagnostic.Message)
		}
	}
	stubAbsolute, err := filepath.Abs(stubPath)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime path: %w", err)
	}
	outputAbsolute, err := filepath.Abs(outputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve output path: %w", err)
	}
	if stubAbsolute == outputAbsolute {
		return nil, errors.New("output path must differ from the runtime stub")
	}
	if _, err := Read(stubPath, false); err == nil {
		return nil, errors.New("runtime stub already contains an AnyAPI payload")
	} else if !errors.Is(err, ErrNotArtifact) {
		return nil, fmt.Errorf("inspect runtime stub: %w", err)
	}
	payload, err := encode(Envelope{Format: FormatVersion, ToolVersion: toolVersion, Document: copyDocument})
	if err != nil {
		return nil, err
	}
	if len(payload) > maxPayload {
		return nil, fmt.Errorf("compiled payload exceeds %d byte limit", maxPayload)
	}
	digest := sha256.Sum256(payload)
	metadata := footer{Magic: magic, FormatVersion: FormatVersion, Codec: CodecCBORZstd, PayloadSize: uint64(len(payload)), PayloadHash: digest}
	// #nosec G304 -- stubPath is an explicit local runtime path selected by the user.
	stub, err := os.Open(stubPath)
	if err != nil {
		return nil, fmt.Errorf("open runtime stub: %w", err)
	}
	defer stub.Close()
	stat, err := stub.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat runtime stub: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return nil, errors.New("runtime stub is not a regular file")
	}
	if stat.Size() > 512<<20 {
		return nil, errors.New("runtime stub exceeds 512 MiB safety limit")
	}
	directory := filepath.Dir(outputPath)
	// #nosec G301 -- generated executables may be intentionally shared; payloads never contain credentials.
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".anyapi-binary-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	succeeded := false
	defer func() {
		if !succeeded {
			_ = temporary.Close()
		}
	}()
	written, err := io.Copy(temporary, io.LimitReader(stub, stat.Size()))
	if err != nil {
		return nil, fmt.Errorf("copy runtime stub: %w", err)
	}
	if written != stat.Size() {
		return nil, fmt.Errorf("runtime stub changed while packing: copied %d of %d bytes", written, stat.Size())
	}
	if _, err := temporary.Write(payload); err != nil {
		return nil, fmt.Errorf("write compiled payload: %w", err)
	}
	if err := binary.Write(temporary, binary.BigEndian, metadata); err != nil {
		return nil, fmt.Errorf("write artifact footer: %w", err)
	}
	mode := stat.Mode().Perm() | 0o500
	if err := temporary.Chmod(mode); err != nil {
		return nil, fmt.Errorf("make artifact executable: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return nil, fmt.Errorf("sync artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return nil, fmt.Errorf("close artifact: %w", err)
	}
	if err := fileutil.Replace(temporaryPath, outputPath); err != nil {
		return nil, fmt.Errorf("publish artifact: %w", err)
	}
	succeeded = true
	return &Info{FormatVersion: FormatVersion, Codec: CodecCBORZstd, PayloadSize: uint64(len(payload)), PayloadSHA256: hex.EncodeToString(digest[:]), ToolVersion: toolVersion, Document: &copyDocument, OutputPath: outputPath}, nil
}

var ErrNotArtifact = errors.New("not an AnyAPI artifact")

func Read(path string, decodeDocument bool) (*Info, error) {
	// #nosec G304 -- path is an explicit document or artifact path supplied by the CLI user.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() < footerSize {
		return nil, ErrNotArtifact
	}
	if _, err := file.Seek(-footerSize, io.SeekEnd); err != nil {
		return nil, err
	}
	var metadata footer
	if err := binary.Read(file, binary.BigEndian, &metadata); err != nil {
		return nil, err
	}
	if metadata.Magic != magic {
		return nil, ErrNotArtifact
	}
	if metadata.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("unsupported artifact format %d", metadata.FormatVersion)
	}
	if metadata.Codec != CodecCBORZstd {
		return nil, fmt.Errorf("unsupported artifact codec %d", metadata.Codec)
	}
	if metadata.Reserved != [12]byte{} {
		return nil, errors.New("artifact footer contains unsupported reserved data")
	}
	if metadata.PayloadSize == 0 || metadata.PayloadSize > maxPayload || int64(metadata.PayloadSize)+footerSize > stat.Size() {
		return nil, errors.New("artifact payload size is invalid")
	}
	payloadOffset := stat.Size() - footerSize - int64(metadata.PayloadSize)
	if payloadOffset <= 0 {
		return nil, errors.New("artifact runtime stub is missing")
	}
	if _, err := file.Seek(payloadOffset, io.SeekStart); err != nil {
		return nil, err
	}
	payload := make([]byte, metadata.PayloadSize)
	if _, err := io.ReadFull(file, payload); err != nil {
		return nil, fmt.Errorf("read artifact payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], metadata.PayloadHash[:]) {
		return nil, errors.New("artifact payload checksum mismatch")
	}
	info := &Info{FormatVersion: metadata.FormatVersion, Codec: metadata.Codec, PayloadSize: metadata.PayloadSize, PayloadSHA256: hex.EncodeToString(digest[:]), OutputPath: path}
	if decodeDocument {
		envelope, err := decode(payload)
		if err != nil {
			return nil, err
		}
		if envelope.Format != FormatVersion {
			return nil, fmt.Errorf("payload format %d does not match footer", envelope.Format)
		}
		envelope.ToolVersion = model.CleanInline(envelope.ToolVersion)
		envelope.Document.Normalize()
		for _, diagnostic := range envelope.Document.AllDiagnostics() {
			if diagnostic.Severity == model.SeverityError {
				return nil, fmt.Errorf("embedded document is invalid at %s: %s", model.CleanText(diagnostic.Path), model.CleanText(diagnostic.Message))
			}
		}
		info.ToolVersion = envelope.ToolVersion
		info.Document = &envelope.Document
	}
	return info, nil
}

func ReadSelf() (*Info, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	return Read(path, true)
}

func encode(envelope Envelope) ([]byte, error) {
	options := cbor.CanonicalEncOptions()
	encoder, err := options.EncMode()
	if err != nil {
		return nil, fmt.Errorf("initialize CBOR encoder: %w", err)
	}
	raw, err := encoder.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}
	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithZeroFrames(true))
	if err != nil {
		return nil, fmt.Errorf("initialize payload compressor: %w", err)
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("compress payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish payload compression: %w", err)
	}
	return compressed.Bytes(), nil
}

func decode(payload []byte) (*Envelope, error) {
	reader, err := zstd.NewReader(bytes.NewReader(payload), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDocument), zstd.WithDecoderMaxWindow(maxDocument))
	if err != nil {
		return nil, fmt.Errorf("initialize payload decompressor: %w", err)
	}
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxDocument+1))
	reader.Close()
	if err != nil {
		return nil, fmt.Errorf("decompress payload: %w", err)
	}
	if len(decompressed) > maxDocument {
		return nil, errors.New("decompressed payload exceeds safety limit")
	}
	decoder, err := cbor.DecOptions{
		MaxNestedLevels:   64,
		MaxArrayElements:  1 << 20,
		MaxMapPairs:       1 << 20,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("initialize CBOR decoder: %w", err)
	}
	var envelope Envelope
	if err := decoder.Unmarshal(decompressed, &envelope); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return &envelope, nil
}
