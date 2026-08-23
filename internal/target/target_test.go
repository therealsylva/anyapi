package target

import (
	"os"
	"testing"
)

func TestDetectCurrentExecutable(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	detected, err := Detect(path)
	if err != nil {
		t.Fatal(err)
	}
	if detected != Native() {
		t.Fatalf("detected %s, native is %s", detected, Native())
	}
}
