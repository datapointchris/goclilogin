package goclilogin

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// ErrNotLoggedIn is returned when no token is stored for the client. It is a
// normal state rather than a fault, so callers branch on it and print a login
// hint instead of an error.
var ErrNotLoggedIn = errors.New("not logged in")

// storedToken is the on-disk shape. oauth2.Token keeps the id_token only in its
// Extra map, which does not survive a JSON round-trip, so it is persisted
// explicitly alongside the standard fields.
type storedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
	IDToken      string    `json:"id_token,omitempty"`
}

func (s storedToken) toOAuth2() *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		TokenType:    s.TokenType,
		Expiry:       s.Expiry,
	}
	if s.IDToken != "" {
		tok = tok.WithExtra(map[string]any{"id_token": s.IDToken})
	}
	return tok
}

func fromOAuth2(tok *oauth2.Token) storedToken {
	s := storedToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
	}
	if id, ok := tok.Extra("id_token").(string); ok {
		s.IDToken = id
	}
	return s
}

// keyringBackend is the seam that lets tests swap the OS keychain for an
// in-memory fake. go-keyring's own MockInit is process-global and racy under
// parallel tests, so the store depends on this interface instead.
type keyringBackend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

// Backend names where a token came from or went. Two stores mean "where is my
// token" has an answer worth reporting: a login says when it had to fall back,
// and a status command says which one is in play.
type Backend string

const (
	// BackendKeyring is the OS keychain, which is where a token belongs.
	BackendKeyring Backend = "OS keyring"

	// BackendFile is the mode-600 fallback file, used only where there is no
	// keyring at all.
	BackendFile Backend = "file"
)

// TokenStore persists OAuth tokens, in the OS keychain wherever there is one
// and in a mode-600 file where there is not.
type TokenStore struct {
	service string
	backend keyringBackend
	file    *fileStore

	// goos decides how a keyring failure is attributed, and attribution decides
	// whether the fallback file is reached at all. It is a field rather than a
	// read of runtime.GOOS at the call site so a test can drive the macOS policy
	// from any machine — the alternative is a rule that only ever runs on the
	// platform nobody runs CI on.
	goos string
}

// NewTokenStore returns a store for cfg: the keychain under cfg.KeyringService,
// with the fallback file inside cfg.StateDir.
func NewTokenStore(cfg Config) *TokenStore {
	return &TokenStore{
		service: cfg.KeyringService,
		backend: osKeyring{},
		file:    newFileStore(cfg.stateDir()),
		goos:    runtime.GOOS,
	}
}

// NewTestTokenStore returns a store backed by an in-memory keyring. It exists so
// a consumer can test its own command wiring without touching the real keychain,
// which is shared machine state that tests must not write.
func NewTestTokenStore(cfg Config) *TokenStore {
	return &TokenStore{
		service: cfg.KeyringService,
		backend: newMemoryKeyring(),
		file:    newFileStore(cfg.stateDir()),
		goos:    runtime.GOOS,
	}
}

// FilePath reports the fallback file, so a caller told the token went there can
// name it.
func (t *TokenStore) FilePath() string { return t.file.Path() }

// Save writes the token for clientID and reports which backend took it.
//
// On Linux the keyring is the Secret Service over D-Bus, and a host without one
// fails before any request is made — a bare Ubuntu userland answers
// `exec: "dbus-launch": executable file not found in $PATH`. Refusing to store a
// token there would make the CLI unusable on exactly the machines that have no
// browser to fall back to. The token goes to a mode-600 file instead, and the
// backend is returned rather than swallowed: a downgrade from keychain to
// plaintext is not something to find out about later.
//
// A keyring the host demonstrably has is a different matter, and Save refuses
// rather than downgrading. A locked macOS keychain is a condition of the session
// and clears with one command, but a token written to the file outlives it —
// Load prefers the keyring only while the keyring holds something, so the
// plaintext copy keeps being used until a re-login moves it back. Trading a
// transient failure for a durable plaintext secret is not a trade the caller
// asked for, so the error names the fix instead.
//
// The id token rides along in a field of its own, because oauth2.Token keeps it
// in an Extra map that does not survive a JSON round-trip.
func (t *TokenStore) Save(clientID string, tok *oauth2.Token) (Backend, error) {
	stored := fromOAuth2(tok)
	data, err := json.Marshal(stored)
	if err != nil {
		return "", err
	}

	keyringErr := t.backend.Set(t.service, clientID, string(data))
	if keyringErr == nil {
		return BackendKeyring, nil
	}

	diag := diagnoseKeyring(t.goos, keyringErr)
	if diag.Cause.keyringPresent() {
		return "", diag
	}

	if err := t.file.Set(clientID, stored); err != nil {
		return "", fmt.Errorf("%s, and the fallback file failed: %w", diag.Reason, err)
	}
	return BackendFile, nil
}

// Load returns the stored token for clientID and where it came from, or
// ErrNotLoggedIn when neither store holds one. A missing entry is a normal state
// rather than a fault, so callers branch on it and print a login hint.
//
// The keyring wins whenever it actually holds something, so a host that gains a
// Secret Service later moves onto it without a re-login.
func (t *TokenStore) Load(clientID string) (*oauth2.Token, Backend, error) {
	raw, keyringErr := t.backend.Get(t.service, clientID)
	if keyringErr == nil && raw != "" {
		var s storedToken
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return nil, "", err
		}
		return s.toOAuth2(), BackendKeyring, nil
	}

	stored, err := t.file.Get(clientID)
	if err != nil {
		return nil, "", err
	}
	if stored != nil {
		return stored.toOAuth2(), BackendFile, nil
	}

	// Nothing anywhere. When the keyring failed for a reason other than an absent
	// entry, that reason is the actionable part: on a host with no Secret Service
	// the fix is a login, which will use the file, but on a machine that has one
	// it is an unlocked keychain — and a bare ErrNotLoggedIn sends the user off to
	// re-authenticate against a store that was never the problem.
	if keyringErr != nil && !errors.Is(keyringErr, keyring.ErrNotFound) {
		reason := diagnoseKeyring(t.goos, keyringErr).Reason
		return nil, "", fmt.Errorf("%w (%s)", ErrNotLoggedIn, reason)
	}
	return nil, "", ErrNotLoggedIn
}

// Delete forgets the token in both stores rather than in the first one that
// answers, returning ErrNotLoggedIn when neither held one. A token written to
// the file before that host had a keyring would otherwise survive the logout
// meant to remove it.
//
// It does not revoke the grant at the provider — this machine simply forgets it.
func (t *TokenStore) Delete(clientID string) error {
	keyringErr := t.backend.Delete(t.service, clientID)
	fileErr := t.file.Delete(clientID)

	if fileErr != nil && !errors.Is(fileErr, ErrNotLoggedIn) {
		return fileErr
	}
	if keyringErr == nil || fileErr == nil {
		return nil
	}
	return ErrNotLoggedIn
}
