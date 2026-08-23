package output

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/therealsylva/anyapi/internal/httpengine"
)

func TestPreparedRedactsSensitiveHeaders(t *testing.T) {
	var buffer bytes.Buffer
	prepared := &httpengine.Prepared{Method: "GET", URL: "https://example.test", Headers: http.Header{"Authorization": {"Bearer secret"}, "Accept": {"application/json"}}}
	if err := Prepared(&buffer, prepared); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buffer.String(), "secret") || !strings.Contains(buffer.String(), "[redacted]") {
		t.Fatalf("header was not redacted: %s", buffer.String())
	}
}

func TestPreparedRedactsQueryAndJSONBody(t *testing.T) {
	var buffer bytes.Buffer
	prepared := &httpengine.Prepared{
		Method:           "POST",
		URL:              "https://example.test/users?key=top-secret&view=full",
		Headers:          http.Header{"X-Credential": {"top-secret"}, "Content-Type": {"application/json"}},
		Body:             []byte(`{"profile":{"pin":"1234"},"password":"hunter2","name":"Ada"}`),
		SensitiveQuery:   map[string]bool{"key": true},
		SensitiveHeaders: map[string]bool{"x-credential": true},
		SensitiveBody:    []string{"profile.pin"},
	}
	if err := Prepared(&buffer, prepared); err != nil {
		t.Fatal(err)
	}
	text := buffer.String()
	for _, secret := range []string{"top-secret", "hunter2", "1234"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q remained in dry-run output: %s", secret, text)
		}
	}
	if !strings.Contains(text, "view=full") || !strings.Contains(text, `"name": "Ada"`) {
		t.Fatalf("non-sensitive values were lost: %s", text)
	}
}

func TestTableOutput(t *testing.T) {
	var buffer bytes.Buffer
	if err := Response(&buffer, []byte(`[{"id":1,"name":"one"},{"id":2,"name":"two"}]`), http.Header{}, "table", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "name") || !strings.Contains(buffer.String(), "two") {
		t.Fatalf("unexpected table: %s", buffer.String())
	}
}

func TestStructuredOutputRejectsTrailingJSON(t *testing.T) {
	var buffer bytes.Buffer
	if err := Response(&buffer, []byte(`{"ok":true}{"extra":true}`), http.Header{}, "json", false); err == nil {
		t.Fatal("expected trailing JSON value to fail")
	}
}

func TestTableOutputTruncatesUnicodeSafely(t *testing.T) {
	var buffer bytes.Buffer
	value := strings.Repeat("界", 60)
	body := []byte(`[{"value":"` + value + `"}]`)
	if err := Response(&buffer, body, http.Header{}, "table", true); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(buffer.String()) || !strings.Contains(buffer.String(), "...") {
		t.Fatalf("invalid truncated output: %q", buffer.String())
	}
}

func TestTableOutputRemovesTerminalControlCharacters(t *testing.T) {
	var buffer bytes.Buffer
	body := []byte("[{\"value\":\"safe\\u001b[31m red\\u202e hidden\\nnext\"}]")
	if err := Response(&buffer, body, http.Header{}, "table", true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buffer.String(), "\x1b") || strings.Contains(buffer.String(), "\u202e") || !strings.Contains(buffer.String(), "safe") {
		t.Fatalf("unsafe table output: %q", buffer.String())
	}
}
