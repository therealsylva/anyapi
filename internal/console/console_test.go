package console

import "testing"

func TestHistorySafeSkipsPotentialSecrets(t *testing.T) {
	tests := []struct {
		tokens []string
		want   bool
	}{
		{tokens: []string{"show", "commands"}, want: true},
		{tokens: []string{"run", "users", "get"}, want: false},
		{tokens: []string{"import", "--curl", "curl https://example.test"}, want: false},
		{tokens: []string{"open", "token-backup.anyapi"}, want: false},
		{tokens: []string{"build", "--output", "users"}, want: true},
	}
	for _, test := range tests {
		if got := historySafe(test.tokens); got != test.want {
			t.Fatalf("historySafe(%q) = %t, want %t", test.tokens, got, test.want)
		}
	}
}

func TestPathAndForceParsing(t *testing.T) {
	path, force, err := pathAndForce([]string{"--force", "users.anyapi"})
	if err != nil || path != "users.anyapi" || !force {
		t.Fatalf("path=%q force=%t error=%v", path, force, err)
	}
	if _, _, err := pathAndForce([]string{"first", "second"}); err == nil {
		t.Fatal("multiple paths were accepted")
	}
}
