package goclilogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// maxCommandStderr is the most of a failed token command's stderr its error
// carries, so a command that dumps a trace does not bury the message.
const maxCommandStderr = 2000

// CommandTokenSource returns a token source that runs command, an argv rather
// than a shell line, for each token it needs. It is for a CLI whose tokens are
// handed to it by something else on the machine, such as a workload's broker,
// the way AWS credential_process and kubectl's exec credential plugins work.
//
// The command prints a token response to stdout, the JSON a token endpoint
// answers with (RFC 6749 §5.1): access_token, and optionally token_type and
// expires_in. A token_type other than Bearer is refused. A token is reused
// until expires_in, counted from when the command started, runs out. One
// without expires_in is reused for the life of the process.
//
// A command that exits non-zero is a *TokenCommandError carrying its stderr.
// ClassifySession reports it as SessionUnverified, because no provider stated
// a refusal. The command runs with the process's environment, and is killed
// when ctx ends.
func CommandTokenSource(ctx context.Context, command []string) (oauth2.TokenSource, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, errors.New("a token command names the program to run")
	}
	return oauth2.ReuseTokenSource(nil, &commandSource{ctx: ctx, argv: slices.Clone(command)}), nil
}

// TokenCommandError is a token command that did not print a token.
type TokenCommandError struct {
	Command []string
	// Stderr is what the command wrote to stderr, trimmed and cut to a length
	// a message can carry.
	Stderr string
	Err    error
}

func (e *TokenCommandError) Error() string {
	msg := fmt.Sprintf("token command %s: %v", strings.Join(e.Command, " "), e.Err)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *TokenCommandError) Unwrap() error { return e.Err }

type commandSource struct {
	ctx  context.Context
	argv []string
}

// tokenResponse is the part of an RFC 6749 §5.1 token response a command
// prints that this package reads.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *commandSource) Token() (*oauth2.Token, error) {
	cmd := exec.CommandContext(c.ctx, c.argv[0], c.argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	started := time.Now()
	if err := cmd.Run(); err != nil {
		return nil, c.fail(err, stderr.String())
	}
	var answer tokenResponse
	if err := json.Unmarshal(stdout.Bytes(), &answer); err != nil {
		return nil, c.fail(fmt.Errorf("its output is not a token response: %w", err), stderr.String())
	}
	switch {
	case answer.AccessToken == "":
		return nil, c.fail(errors.New("it printed no access_token"), stderr.String())
	case answer.TokenType != "" && !strings.EqualFold(answer.TokenType, "bearer"):
		return nil, c.fail(fmt.Errorf("it printed a %s token, and only a bearer token is sent", answer.TokenType), stderr.String())
	case answer.ExpiresIn < 0:
		return nil, c.fail(fmt.Errorf("it printed expires_in %d", answer.ExpiresIn), stderr.String())
	}
	token := &oauth2.Token{AccessToken: answer.AccessToken, TokenType: "Bearer"}
	if answer.ExpiresIn > 0 {
		token.Expiry = started.Add(time.Duration(answer.ExpiresIn) * time.Second)
	}
	return token, nil
}

func (c *commandSource) fail(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if len(stderr) > maxCommandStderr {
		stderr = stderr[:maxCommandStderr] + "…"
	}
	return &TokenCommandError{Command: c.argv, Stderr: stderr, Err: err}
}
