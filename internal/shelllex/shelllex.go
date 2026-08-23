package shelllex

import (
	"fmt"
	"strings"
	"unicode"
)

// Split tokenizes a shell-like command without performing expansion,
// substitution, globbing, file reads, or command execution.
func Split(input string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	started := false
	flush := func() {
		if started {
			tokens = append(tokens, current.String())
			current.Reset()
			started = false
		}
	}
	for _, char := range input {
		if escaped {
			if quote == '"' && char == '\n' {
				escaped = false
				continue
			}
			if quote == '"' && !strings.ContainsRune("$`\"\\", char) {
				current.WriteRune('\\')
			}
			current.WriteRune(char)
			escaped = false
			started = true
			continue
		}
		if char == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			started = true
			continue
		}
		switch {
		case char == '\'' || char == '"':
			quote = char
			started = true
		case unicode.IsSpace(char):
			flush()
		default:
			current.WriteRune(char)
			started = true
		}
	}
	if escaped {
		return nil, fmt.Errorf("unfinished escape sequence")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	flush()
	return tokens, nil
}
