package goclilogin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tokenCommand writes an executable shell script running body, and returns its
// path. Each run appends a line to the returned count file.
func tokenCommand(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	script := filepath.Join(dir, "token")
	content := "#!/bin/sh\necho run >> '" + runs + "'\n" + body + "\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, runs
}

func countRuns(t *testing.T, runs string) int {
	t.Helper()
	data, err := os.ReadFile(runs)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "run\n")
}

func TestCommandTokenSource_ReusesTheHandedTokenUntilItExpires(t *testing.T) {
	script, runs := tokenCommand(t, `echo '{"access_token": "handed", "token_type": "Bearer", "expires_in": 300}'`)
	source, err := CommandTokenSource(context.Background(), []string{script})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		token, err := source.Token()
		if err != nil {
			t.Fatal(err)
		}
		if token.AccessToken != "handed" || token.Type() != "Bearer" || token.Expiry.IsZero() {
			t.Fatalf("token = %+v", token)
		}
	}
	if n := countRuns(t, runs); n != 1 {
		t.Fatalf("the command ran %d times for three tokens inside its expiry", n)
	}
}

func TestCommandTokenSource_AFailedCommandNamesItselfAndItsStderr(t *testing.T) {
	script, _ := tokenCommand(t, "echo 'the broker refused run 12' >&2\nexit 3")
	source, err := CommandTokenSource(context.Background(), []string{script, "myapp"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Token()
	var failed *TokenCommandError
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want a *TokenCommandError", err)
	}
	if !strings.Contains(err.Error(), script+" myapp") || failed.Stderr != "the broker refused run 12" {
		t.Fatalf("err = %v", err)
	}
	if state, _ := ClassifySession(nil, err); state != SessionUnverified {
		t.Fatalf("state = %v, want SessionUnverified", state)
	}
}

func TestLoadDeployment_ATokenCommandNeedsOnlyTheAPI(t *testing.T) {
	configHome(t)
	writeConfig(t, "myapp", `api = "https://myapp.example.com"
token_command = ["broker", "token", "myapp"]
`)
	d, err := LoadDeployment(context.Background(), "myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	if !d.HandsTokens() || strings.Join(d.TokenCommand.Argv(), " ") != "broker token myapp" {
		t.Fatalf("token command = %q", d.TokenCommand.Argv())
	}
	if _, err := DeploymentForLogin(context.Background(), "myapp", "", ""); err == nil || !strings.Contains(err.Error(), "never logs in") {
		t.Fatalf("login with a token command: err = %v", err)
	}
}
