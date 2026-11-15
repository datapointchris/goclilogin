package goclilogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	helperModeEnv = "GOCLILOGIN_TOKEN_COMMAND_HELPER"
	helperRunsEnv = "GOCLILOGIN_TOKEN_COMMAND_RUNS"
)

// TestTokenCommandHelper is the token command the tests run. It is the test
// binary itself because Windows cannot exec a shell script. It does nothing
// unless a test set helperModeEnv.
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
	switch {
	case mode == "token":
		fmt.Println(`{"access_token": "handed", "token_type": "Bearer", "expires_in": 300}`)
		os.Exit(0)
	case strings.HasPrefix(mode, "print:"):
		fmt.Println(strings.TrimPrefix(mode, "print:"))
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

// A command that exits zero but prints an answer no request can carry is
// refused, rather than sending an empty or non-bearer Authorization header.
func TestCommandTokenSource_RefusesAnAnswerNoRequestCanCarry(t *testing.T) {
	tests := []struct {
		name   string
		output string
		names  string // the part of the output the refusal names, or "" for a JSON syntax error
	}{
		{name: "no access_token", output: `{"token_type": "Bearer", "expires_in": 300}`, names: "access_token"},
		{name: "a token type other than Bearer", output: `{"access_token": "handed", "token_type": "MAC"}`, names: "MAC"},
		{name: "a negative expires_in", output: `{"access_token": "handed", "expires_in": -5}`, names: "-5"},
		{name: "output that is not JSON", output: `handed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, _ := tokenCommand(t, "print:"+tt.output)
			source, err := CommandTokenSource(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			token, err := source.Token()
			var failed *TokenCommandError
			if token != nil || !errors.As(err, &failed) {
				t.Fatalf("token = %+v, err = %v, want no token and a *TokenCommandError", token, err)
			}
			if tt.names == "" {
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) {
					t.Errorf("err = %v, want it to wrap a *json.SyntaxError", err)
				}
			} else if !strings.Contains(failed.Err.Error(), tt.names) {
				t.Errorf("err = %v, want it to name %q", failed.Err, tt.names)
			}
		})
	}
}

// A token_command naming no program, and an --api the file has no issuer to
// check, are each refused when the file is read, before any request is made.
func TestLoadDeployment_RefusesATokenCommandFileItCannotUse(t *testing.T) {
	var metadataRequests atomic.Int32
	other := serveMetadata(t, func(base string) *protectedResourceMetadata {
		metadataRequests.Add(1)
		return &protectedResourceMetadata{Resource: base, AuthorizationServers: []string{"https://auth.example.com"}}
	})
	tests := []struct {
		name string
		file string
		api  string
	}{
		{name: "an empty token_command", file: "api = \"https://myapp.example.com\"\ntoken_command = []\n"},
		{name: "a token_command naming no program", file: "api = \"https://myapp.example.com\"\ntoken_command = [\"\", \"token\"]\n"},
		{name: "an --api the file names no issuer for", file: "api = \"https://myapp.example.com\"\ntoken_command = [\"broker\", \"token\"]\n", api: other.URL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configHome(t)
			path := writeConfig(t, "myapp", tt.file)
			_, err := LoadDeployment(context.Background(), "myapp", tt.api)
			if err == nil || errors.Is(err, ErrNotConfigured) {
				t.Fatalf("err = %v, want a refusal that is not ErrNotConfigured", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("err = %v, want it to name %s", err, path)
			}
		})
	}
	if n := metadataRequests.Load(); n != 0 {
		t.Errorf("the --api was asked for its metadata %d times, want 0", n)
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
