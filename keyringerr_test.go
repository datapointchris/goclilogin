package goclilogin

import (
	"errors"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
)

// exitErrorWithCode runs a process that exits with code, because an
// *exec.ExitError carries an os.ProcessState that cannot be constructed — the
// only way to get one holding a chosen status is to produce it.
func exitErrorWithCode(t *testing.T, code int) error {
	t.Helper()

	arg := strconv.Itoa(code)
	cmd := exec.Command("sh", "-c", "exit "+arg)
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "exit", arg)
	}

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("wanted an *exec.ExitError carrying %d, got %v", code, err)
	}
	return err
}

// The cause is what Save branches on, so the cause is what is asserted. A locked
// keychain and a keychain that refused for some other reason reach the user as
// different sentences, but the sentence is a rendering — pinning it would test
// that nobody edited a string.
func TestDiagnoseKeyring_AttributesTheCause(t *testing.T) {
	tests := []struct {
		name string
		goos string
		err  error
		want keyringCause
	}{
		{
			// The failure this exists for: over SSH a Mac refuses the keychain,
			// go-keyring drops security's explanation, and "exit status 36" is
			// all that survives.
			name: "a locked login keychain has a named fix",
			goos: "darwin",
			err:  exitErrorWithCode(t, errSecInteractionNotAllowed),
			want: keyringLocked,
		},
		{
			// A Mac always has a keychain, so this refused rather than being
			// absent — but nothing here says why, so nothing here suggests a fix.
			name: "any other status from security refused without saying why",
			goos: "darwin",
			err:  exitErrorWithCode(t, 51),
			want: keyringRefused,
		},
		{
			// A Secret Service error cannot separate a host with no bus from one
			// whose keyring is locked, and this must keep saying so: attributing
			// it would send a headless host to unlock a keyring it does not have.
			name: "a Secret Service failure names neither cause",
			goos: "linux",
			err:  errNoDBus,
			want: keyringUnattributed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := diagnoseKeyring(tt.goos, tt.err).Cause; got != tt.want {
				t.Errorf("Cause = %s, want %s", got, tt.want)
			}
		})
	}
}
