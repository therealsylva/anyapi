package banner

import (
	"strings"
	"testing"
)

func TestTextUsesUnicodeBannerInUTF8Locale(t *testing.T) {
	t.Setenv("ANYAPI_BANNER", "")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LC_ALL", "C.UTF-8")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "")
	if got := Text(); got != Unicode || !strings.Contains(got, "██████") {
		t.Fatalf("unexpected Unicode banner: %q", got)
	}
}

func TestTextUsesPlainBannerForDumbTerminal(t *testing.T) {
	t.Setenv("ANYAPI_BANNER", "")
	t.Setenv("TERM", "dumb")
	if got := Text(); got != Plain {
		t.Fatalf("plain banner = %q", got)
	}
}

func TestLCAllTakesPrecedence(t *testing.T) {
	t.Setenv("ANYAPI_BANNER", "")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "C.UTF-8")
	t.Setenv("LANG", "en_US.UTF-8")
	if got := Text(); got != Plain {
		t.Fatalf("plain banner = %q", got)
	}
}
