package goclilogin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// deadKeyring is a host with no Secret Service. go-keyring fails before any
// request is made, with exactly this shape of error: not "no entry", but "the
// mechanism is missing".
type deadKeyring struct{}

var errNoDBus = errors.New(`exec: "dbus-launch": executable file not found in $PATH`)

func (deadKeyring) Set(string, string, string) error { return errNoDBus }
func (deadKeyring) Get(string, string) (string, error) {
	return "", errNoDBus
}
func (deadKeyring) Delete(string, string) error { return errNoDBus }

func keyringlessStore(t *testing.T) (*TokenStore, Config) {
	t.Helper()
	cfg := Config{
		Issuer:         "https://auth.example.com",
		ClientID:       "prod-cli-testhost",
		KeyringService: "prod-cli",
		StateDir:       t.TempDir(),
	}
	return &TokenStore{
		service: cfg.KeyringService,
		backend: deadKeyring{},
		file:    newFileStore(cfg.stateDir()),
	}, cfg
}

func sampleToken() *oauth2.Token {
	return (&oauth2.Token{
		AccessToken:  "at-1",
		RefreshToken: "rt-1",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour).Truncate(time.Second),
	}).WithExtra(map[string]any{"id_token": "id-1"})
}

// Refusing to store a token on a keyringless host would make the CLI unusable
// on exactly the machines that have no browser to fall back to.
func TestSave_FallsBackToTheFileAndSaysSo(t *testing.T) {
	store, cfg := keyringlessStore(t)

	backend, err := store.Save(cfg.ClientID, sampleToken())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if backend != BackendFile {
		t.Errorf("backend = %q, want %q — the downgrade has to be reported", backend, BackendFile)
	}
}

// A plaintext token file that anyone on the box can read is the thing this mode
// is trading away, so the mode is asserted rather than assumed.
func TestSave_WritesTheFallbackFile0600(t *testing.T) {
	store, cfg := keyringlessStore(t)
	if _, err := store.Save(cfg.ClientID, sampleToken()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(store.FilePath())
	if err != nil {
		t.Fatalf("stat the fallback file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// A state directory the library has to create is created private. One the
// caller already made is left as the caller made it — its mode is theirs, not
// this package's to change under them.
func TestSave_CreatesAMissingStateDirectory0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	store := &TokenStore{service: "prod-cli", backend: deadKeyring{}, file: newFileStore(dir)}

	if _, err := store.Save("prod-cli-testhost", sampleToken()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat the state directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %o, want 700", perm)
	}
}

func TestLoad_ReadsBackWhatTheFallbackStored(t *testing.T) {
	store, cfg := keyringlessStore(t)
	want := sampleToken()
	if _, err := store.Save(cfg.ClientID, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, backend, err := store.Load(cfg.ClientID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if backend != BackendFile {
		t.Errorf("backend = %q, want %q", backend, BackendFile)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Errorf("token = %+v, want the saved one", got)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Errorf("expiry = %v, want %v", got.Expiry, want.Expiry)
	}
	// The id token lives in an Extra map that does not survive a plain JSON
	// round-trip, which is why storedToken carries it in a field of its own.
	if id, _ := got.Extra("id_token").(string); id != "id-1" {
		t.Errorf("id_token = %q, want id-1", id)
	}
}

// A host that gains a Secret Service later must move onto it without a
// re-login, so the keyring wins whenever it actually holds something.
func TestLoad_PrefersTheKeyringOverAStaleFileToken(t *testing.T) {
	cfg := Config{ClientID: "prod-cli-testhost", KeyringService: "prod-cli", StateDir: t.TempDir()}

	// Write a file token the way a keyringless run would have.
	fileOnly := &TokenStore{service: cfg.KeyringService, backend: deadKeyring{}, file: newFileStore(cfg.stateDir())}
	if _, err := fileOnly.Save(cfg.ClientID, &oauth2.Token{AccessToken: "at-from-file", TokenType: "bearer"}); err != nil {
		t.Fatalf("seed the file: %v", err)
	}

	// The same machine, now with a working keyring holding a newer token.
	revived := &TokenStore{service: cfg.KeyringService, backend: newMemoryKeyring(), file: newFileStore(cfg.stateDir())}
	if _, err := revived.Save(cfg.ClientID, &oauth2.Token{AccessToken: "at-from-keyring", TokenType: "bearer"}); err != nil {
		t.Fatalf("seed the keyring: %v", err)
	}

	got, backend, err := revived.Load(cfg.ClientID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if backend != BackendKeyring || got.AccessToken != "at-from-keyring" {
		t.Errorf("got %q from %q, want the keyring's token", got.AccessToken, backend)
	}
}

// A token written to the file before that host had a keyring would otherwise
// survive the logout meant to remove it, and keep authenticating.
func TestDelete_ClearsBothStores(t *testing.T) {
	cfg := Config{ClientID: "prod-cli-testhost", KeyringService: "prod-cli", StateDir: t.TempDir()}

	fileOnly := &TokenStore{service: cfg.KeyringService, backend: deadKeyring{}, file: newFileStore(cfg.stateDir())}
	if _, err := fileOnly.Save(cfg.ClientID, sampleToken()); err != nil {
		t.Fatalf("seed the file: %v", err)
	}

	revived := &TokenStore{service: cfg.KeyringService, backend: newMemoryKeyring(), file: newFileStore(cfg.stateDir())}
	if _, err := revived.Save(cfg.ClientID, sampleToken()); err != nil {
		t.Fatalf("seed the keyring: %v", err)
	}

	if err := revived.Delete(cfg.ClientID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := revived.Load(cfg.ClientID); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after Delete, Load returned %v — a store still holds the token", err)
	}
}

// "Not logged in" and "your keychain is locked" need different fixes, and a
// bare ErrNotLoggedIn sends the user to re-authenticate against a store that
// was never the problem.
func TestLoad_NamesTheKeyringFailureWhenNothingIsStored(t *testing.T) {
	store, cfg := keyringlessStore(t)

	_, _, err := store.Load(cfg.ClientID)
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want it to wrap ErrNotLoggedIn", err)
	}
	if !strings.Contains(err.Error(), "dbus-launch") {
		t.Errorf("err = %v, want the keyring's own reason carried through", err)
	}
}

// An absent entry is not a broken keyring, so it must not be dressed up as one.
func TestLoad_PlainNotLoggedInWhenTheKeyringSimplyHasNoEntry(t *testing.T) {
	cfg := Config{ClientID: "prod-cli-testhost", KeyringService: "prod-cli", StateDir: t.TempDir()}
	store := &TokenStore{service: cfg.KeyringService, backend: newMemoryKeyring(), file: newFileStore(cfg.stateDir())}

	_, _, err := store.Load(cfg.ClientID)
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
	if strings.Contains(err.Error(), "unavailable") {
		t.Errorf("err = %v, want no keyring-failure noise for a simple miss", err)
	}
}

// A corrupt file cannot be recovered by starting over: treating it as empty
// would report "not logged in" for a token sitting right there, and the next
// login would overwrite it.
func TestLoad_RefusesACorruptFallbackFile(t *testing.T) {
	store, cfg := keyringlessStore(t)
	if err := os.MkdirAll(filepath.Dir(store.FilePath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.FilePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := store.Load(cfg.ClientID)
	if err == nil || errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want a parse failure rather than a silent miss", err)
	}
}

// With no state directory there is no private place for a secret, so the store
// refuses instead of dropping a token somewhere world-readable.
func TestSave_RefusesWithNoStateDirectory(t *testing.T) {
	store := &TokenStore{service: "prod-cli", backend: deadKeyring{}, file: newFileStore("")}

	if _, err := store.Save("prod-cli-testhost", sampleToken()); err == nil {
		t.Fatal("expected a refusal when there is nowhere private to write")
	}
}
