package goclilogin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// tokenFileName is the fallback store's file, inside the caller's StateDir.
//
// The state directory rather than the config directory: config is a file to
// hand-edit and paste out of, and a secret must not sit one field away from
// that.
const tokenFileName = "token.json"

// fileStore keeps tokens in a 0600 JSON file, for hosts with no OS keyring at
// all — WSL, containers, any headless server. Keyed by the same client id as
// the keyring, so the two backends address one token.
type fileStore struct {
	path string
}

func newFileStore(stateDir string) *fileStore {
	if stateDir == "" {
		// No state directory means no private place to put a secret. An empty
		// path makes the backend refuse rather than drop a token somewhere
		// world-readable.
		return &fileStore{}
	}
	return &fileStore{path: filepath.Join(stateDir, tokenFileName)}
}

func (f *fileStore) Path() string { return f.path }

// Get returns a nil token when nothing is stored, leaving "absent" for the
// caller to interpret — it has to weigh a missing file token against whatever
// the keyring said before deciding the user is not logged in.
func (f *fileStore) Get(clientID string) (*storedToken, error) {
	if f.path == "" {
		return nil, nil
	}
	tokens, err := f.load()
	if err != nil {
		return nil, err
	}
	stored, ok := tokens[clientID]
	if !ok {
		return nil, nil
	}
	return &stored, nil
}

func (f *fileStore) Set(clientID string, stored storedToken) error {
	if f.path == "" {
		return errors.New("no state directory to store a token in: set XDG_STATE_HOME, or give Config a StateDir")
	}
	tokens, err := f.load()
	if err != nil {
		return err
	}
	tokens[clientID] = stored
	return f.write(tokens)
}

func (f *fileStore) Delete(clientID string) error {
	if f.path == "" {
		return ErrNotLoggedIn
	}
	tokens, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := tokens[clientID]; !ok {
		return ErrNotLoggedIn
	}
	delete(tokens, clientID)
	return f.write(tokens)
}

func (f *fileStore) load() (map[string]storedToken, error) {
	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return map[string]storedToken{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", f.path, err)
	}

	tokens := map[string]storedToken{}
	if err := json.Unmarshal(data, &tokens); err != nil {
		// Treating a corrupt file as empty would report "not logged in" for a
		// token sitting right there, and the next login would overwrite it.
		return nil, fmt.Errorf("parsing %s: %w", f.path, err)
	}
	return tokens, nil
}

// write replaces the file atomically, so an interrupt cannot leave a truncated
// token behind. os.CreateTemp already creates the file 0600, but the mode is set
// explicitly as well: this is the line that keeps the token from being world
// readable, and it should not survive only as a property of the helper.
func (f *fileStore) write(tokens map[string]storedToken) error {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}

	temp, err := os.CreateTemp(dir, ".token-*.json")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()

	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempName, 0o600); err != nil {
		return err
	}
	return os.Rename(tempName, f.path)
}
