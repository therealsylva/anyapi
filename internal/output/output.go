package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/therealsylva/anyapi/internal/httpengine"
	"go.yaml.in/yaml/v3"
)

func Response(writer io.Writer, body []byte, headers http.Header, mode string, pretty bool) error {
	mode = strings.ToLower(mode)
	if mode == "" || mode == "auto" {
		contentType := strings.ToLower(headers.Get("Content-Type"))
		if strings.Contains(contentType, "json") && pretty {
			mode = "json"
		} else {
			mode = "raw"
		}
	}
	switch mode {
	case "raw":
		_, err := writer.Write(body)
		if err == nil && len(body) > 0 && body[len(body)-1] != '\n' && utf8.Valid(body) {
			_, err = io.WriteString(writer, "\n")
		}
		return err
	case "json":
		value, err := decodeJSON(body)
		if err != nil {
			return fmt.Errorf("response is not valid JSON: %w", err)
		}
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		if pretty {
			encoder.SetIndent("", "  ")
		}
		return encoder.Encode(value)
	case "yaml":
		value, err := decodeJSON(body)
		if err != nil {
			return fmt.Errorf("response is not valid JSON: %w", err)
		}
		data, err := yaml.Marshal(value)
		if err != nil {
			return err
		}
		_, err = writer.Write(data)
		return err
	case "table":
		return renderTable(writer, body)
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func Prepared(writer io.Writer, prepared *httpengine.Prepared) error {
	if prepared == nil {
		return nil
	}
	if _, err := fmt.Fprintf(writer, "%s %s\n", prepared.Method, prepared.RedactedURL()); err != nil {
		return err
	}
	keys := make([]string, 0, len(prepared.Headers))
	for key := range prepared.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := terminalCell(strings.Join(prepared.Headers.Values(key), ", "))
		if sensitiveHeader(key) || prepared.SensitiveHeaders[strings.ToLower(key)] {
			value = "[redacted]"
		}
		if _, err := fmt.Fprintf(writer, "%s: %s\n", key, value); err != nil {
			return err
		}
	}
	if len(prepared.Body) > 0 {
		if _, err := io.WriteString(writer, "\n"); err != nil {
			return err
		}
		if json.Valid(prepared.Body) {
			var value any
			decoder := json.NewDecoder(bytes.NewReader(prepared.Body))
			decoder.UseNumber()
			if decoder.Decode(&value) == nil {
				redactJSON(value)
				for _, path := range prepared.SensitiveBody {
					redactJSONPath(value, path)
				}
				encoder := json.NewEncoder(writer)
				encoder.SetEscapeHTML(false)
				encoder.SetIndent("", "  ")
				return encoder.Encode(value)
			}
		}
		_, err := fmt.Fprintf(writer, "[%d-byte request body]\n", len(prepared.Body))
		return err
	}
	return nil
}

func redactJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if sensitiveHeader(key) {
				typed[key] = "[redacted]"
				continue
			}
			redactJSON(item)
		}
	case []any:
		for _, item := range typed {
			redactJSON(item)
		}
	}
}

func redactJSONPath(value any, path string) {
	parts := strings.Split(strings.Trim(path, "."), ".")
	if len(parts) == 0 {
		return
	}
	current, ok := value.(map[string]any)
	if !ok {
		return
	}
	for index, part := range parts {
		if index == len(parts)-1 {
			if _, exists := current[part]; exists {
				current[part] = "[redacted]"
			}
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			return
		}
		current = next
	}
}

func renderTable(writer io.Writer, body []byte) error {
	value, err := decodeJSON(body)
	if err != nil {
		return fmt.Errorf("response is not valid JSON: %w", err)
	}
	rows := []map[string]any{}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if row, ok := item.(map[string]any); ok {
				rows = append(rows, row)
			} else {
				rows = append(rows, map[string]any{"value": item})
			}
		}
	case map[string]any:
		rows = append(rows, typed)
	default:
		rows = append(rows, map[string]any{"value": typed})
	}
	if len(rows) == 0 {
		return nil
	}
	columnSet := map[string]bool{}
	for _, row := range rows {
		for key := range row {
			columnSet[key] = true
		}
	}
	columns := make([]string, 0, len(columnSet))
	for key := range columnSet {
		columns = append(columns, key)
	}
	sort.Strings(columns)
	widths := make([]int, len(columns))
	for index, column := range columns {
		widths[index] = utf8.RuneCountInString(column)
	}
	formatted := make([][]string, len(rows))
	for rowIndex, row := range rows {
		formatted[rowIndex] = make([]string, len(columns))
		for columnIndex, column := range columns {
			text := terminalCell(compact(row[column]))
			if utf8.RuneCountInString(text) > 48 {
				text = truncateRunes(text, 45) + "..."
			}
			formatted[rowIndex][columnIndex] = text
			if width := utf8.RuneCountInString(text); width > widths[columnIndex] {
				widths[columnIndex] = width
			}
		}
	}
	writeRow := func(values []string) error {
		for index, value := range values {
			if index > 0 {
				if _, err := io.WriteString(writer, "  "); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(writer, "%-*s", widths[index], value); err != nil {
				return err
			}
		}
		_, err := io.WriteString(writer, "\n")
		return err
	}
	if err := writeRow(columns); err != nil {
		return err
	}
	separators := make([]string, len(columns))
	for index, width := range widths {
		separators[index] = strings.Repeat("-", width)
	}
	if err := writeRow(separators); err != nil {
		return err
	}
	for _, row := range formatted {
		if err := writeRow(row); err != nil {
			return err
		}
	}
	return nil
}

func terminalCell(value string) string {
	return strings.Map(func(character rune) rune {
		switch character {
		case '\n', '\r', '\t':
			return ' '
		}
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return -1
		}
		return character
	}, value)
}

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return value, nil
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func compact(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.ReplaceAll(typed, "\n", " ")
	case json.Number:
		return typed.String()
	case bool:
		return fmt.Sprint(typed)
	default:
		data, _ := json.Marshal(typed)
		return string(data)
	}
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
