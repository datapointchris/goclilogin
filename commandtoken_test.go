package goclilogin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	helperModeEnv = "GOCLILOGIN_TOKEN_COMMAND_HELPER"
	helperRunsEnv = "GOCLILOGIN_TOKEN_COMMAND_RUNS"
)

// TestTokenCommandHelper is the token command the tests run, as the test
// binary itself so it runs on every platform. It does nothing unless a test
// set helperModeEnv.
func TestTokenCommandHelper(t *testing.T) {
	mode := os.Getenv(helperModeEnv)
	if mode == "" {
		return
	}
	runs, err := os.OpenFile(os.Getenv(helperRunsEnv), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = runs.WriteString("run\n")
		_ = runs.Close()
	}
	switch mode {
	case "token":
		fmt.Println(`{"access_token": "handed", "token_type": "Bearer", "expires_in": 300}`)
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "the broker refused run 12")
		os.Exit(3)
	}
}

// tokenCommand is the argv running TestTokenCommandHelper in mode, and the file
// each of its runs appends a line to.
func tokenCommand(t *testing.T, mode string) ([]string, string) {
	t.Helper()
	runs := filepath.Join(t.TempDir(), "runs")
	t.Setenv(helperModeEnv, mode)
	t.Setenv(helperRunsEnv, runs)
	return []string{os.Args[0], "-test.run=^TestTokenCommandHelper$"}, runs
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
	command, runs := tokenCommand(t, "token")
	source, err := CommandTokenSource(context.Background(), command)
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
	command, _ := tokenCommand(t, "refuse")
	source, err := CommandTokenSource(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Token()
	var failed *TokenCommandError
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want a *TokenCommandError", err)
	}
	if !strings.Contains(err.Error(), strings.Join(command, " ")) || failed.Stderr != "the broker refused run 12" {
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
