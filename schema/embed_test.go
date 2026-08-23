package schema

import (
	"encoding/json"
	"testing"
)

func TestEmbeddedSchemaIsValidJSON(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(JSON, &schema); err != nil {
		t.Fatalf("embedded schema is invalid JSON: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected schema dialect: %v", schema["$schema"])
	}
}
