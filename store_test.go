package goclilogin

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/oauth2"
)

// failingKeyring is a keyring that is reachable and answers no, which is the
// shape a locked macOS keychain arrives in.
type failingKeyring struct{ err error }

func (k failingKeyring) Set(string, string, string) error { return k.err }
func (k failingKeyring) Get(string, string) (string, error) {
	return "", k.err
}
func (k failingKeyring) Delete(string, string) error { return k.err }

// Whether the fallback file was written is the value under test. A locked
// keychain clears with one command, but a plaintext token written while it was
// locked outlives the lock — Load prefers the keyring only while the keyring
// holds something — so the transient failure would buy a durable downgrade.
func TestSave_ReachesTheFallbackOnlyWhereAKeyringMayNotExist(t *testing.T) {
	tests := []struct {
		name        string
		goos        string
		keyringErr  error
		wantBackend Backend
		wantFile    bool
	}{
		{
			name:        "a locked login keychain refuses",
			goos:        "darwin",
			keyringErr:  exitErrorWithCode(t, errSecInteractionNotAllowed),
			wantBackend: "",
			wantFile:    false,
		},
		{
			// Unexplained, but still a Mac, and a Mac has a keychain. Nothing
			// forces plaintext here either.
			name:        "a keychain that refused for some other reason refuses too",
			goos:        "darwin",
			keyringErr:  exitErrorWithCode(t, 51),
			wantBackend: "",
			wantFile:    false,
		},
		{
			// The case the fallback was built for. A host with no Secret Service
			// has no browser to fall back to either, so refusing would leave the
			// CLI with no way to log in at all.
			name:        "a host that may have no keyring at all falls back",
			goos:        "linux",
			keyringErr:  errNoDBus,
			wantBackend: BackendFile,
			wantFile:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store := &TokenStore{
				service: "prod-cli",
				backend: failingKeyring{err: tt.keyringErr},
				file:    newFileStore(dir),
				goos:    tt.goos,
			}

			backend, err := store.Save("prod-cli-testhost", &oauth2.Token{
				AccessToken:  "access",
				RefreshToken: "refresh",
			})

			wantErr := !tt.wantFile
			if (err != nil) != wantErr {
				t.Errorf("Save error = %v, want an error: %v", err, wantErr)
			}
			if backend != tt.wantBackend {
				t.Errorf("Backend = %q, want %q", backend, tt.wantBackend)
			}

			_, statErr := os.Stat(filepath.Join(dir, tokenFileName))
			if wroteFile := statErr == nil; wroteFile != tt.wantFile {
				t.Errorf("token file written = %v, want %v", wroteFile, tt.wantFile)
			}
		})
	}
}

// The refusal keeps the provider's own failure reachable, so a caller wanting
// the exit status is not left parsing the sentence back apart.
func TestSave_RefusalUnwrapsToTheProviderError(t *testing.T) {
	keyringErr := exitErrorWithCode(t, errSecInteractionNotAllowed)
	store := &TokenStore{
		service: "prod-cli",
		backend: failingKeyring{err: keyringErr},
		file:    newFileStore(t.TempDir()),
		goos:    "darwin",
	}

	_, err := store.Save("prod-cli-testhost", &oauth2.Token{AccessToken: "access"})
	if err == nil {
		t.Fatal("Save succeeded where it was meant to refuse")
	}
	if !errors.Is(err, keyringErr) {
		t.Errorf("refusal does not unwrap to the provider error: %v", err)
	}
}
