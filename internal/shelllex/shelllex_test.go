package shelllex

import (
	"reflect"
	"testing"
)

func TestSplitQuotesWithoutExpansion(t *testing.T) {
	input := `curl -H 'Authorization: Bearer $TOKEN' "https://example.test/users/${ID}"`
	got, err := Split(input)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"curl", "-H", "Authorization: Bearer $TOKEN", "https://example.test/users/${ID}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestSplitRejectsUnterminatedQuote(t *testing.T) {
	if _, err := Split(`curl 'broken`); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSplitPreservesNonSpecialBackslashesInDoubleQuotes(t *testing.T) {
	got, err := Split(`curl --data "C:\temp\request.json" "https://example.test/\$literal"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"curl", "--data", `C:\temp\request.json`, "https://example.test/$literal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func FuzzSplit(f *testing.F) {
	for _, seed := range []string{"curl https://example.test", `a 'b c'`, `a \\"b`, "", "x\\ y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = Split(value)
	})
}
