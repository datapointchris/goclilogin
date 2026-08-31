package goclilogin

import (
	"errors"
	"os/exec"
)

// errSecInteractionNotAllowed is what macOS reports when a keychain operation
// would have to put a dialog on screen and the session has nowhere to put one.
// The OSStatus is -25308 and an exit status carries only its low byte, which is
// 36 — so what reaches Go is a bare "exit status 36", the sentence security
// printed having gone to a stderr go-keyring does not capture.
const errSecInteractionNotAllowed = 36

// keyringCause is why the OS keyring would not hold a token. Two of these have
// remedies that are wrong for each other, so it is a value a caller branches on
// rather than a sentence a caller would have to read.
type keyringCause int

const (
	// keyringUnattributed is a failure this cannot separate into a keyring that
	// is missing and one that is refusing. Nothing in a Secret Service error
	// distinguishes a host that has no bus from one whose keyring is locked, and
	// picking one costs more than saying nothing.
	keyringUnattributed keyringCause = iota

	// keyringLocked is a keyring that is present and will not unlock without a
	// session that can prompt. It has a named fix, which is what separates it
	// from keyringRefused.
	keyringLocked

	// keyringRefused is a keyring that is present and failed for a reason it did
	// not explain. Naming a fix here would be guessing at an OSStatus nobody has
	// measured.
	keyringRefused
)

func (c keyringCause) String() string {
	switch c {
	case keyringLocked:
		return "locked"
	case keyringRefused:
		return "refused"
	default:
		return "unattributed"
	}
}

// keyringDiagnosis is the attributed cause and the sentence built from it. The
// cause is the value; Reason is what a renderer does with it.
type keyringDiagnosis struct {
	Cause  keyringCause
	Reason string
}

// diagnoseKeyring attributes a keyring failure before either cause is blamed,
// per standards/help.md § "A failure with two causes is attributed before either
// one is blamed". Save and Load both build their message from this, so the same
// failure reads the same whichever door the user came in.
//
// goos is a parameter rather than a read of runtime.GOOS so that every branch is
// reachable from a test on any host. A darwin-only branch behind a build tag
// would be exercised only on a Mac, and the machines this fires on are the ones
// nobody is watching.
func diagnoseKeyring(goos string, err error) keyringDiagnosis {
	if goos == "darwin" {
		// Every Mac has a login keychain, so a failure here is one that refused
		// and never one that was absent. That is the whole attribution: no error
		// string is parsed, so nothing about it can drift.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == errSecInteractionNotAllowed {
			return keyringDiagnosis{
				Cause: keyringLocked,
				Reason: "the login keychain is locked and this session cannot prompt to unlock it" +
					" — run `security unlock-keychain` in this session first" +
					" (an SSH session is the usual way to land here: it does not inherit the console session's keychain access)",
			}
		}
		return keyringDiagnosis{
			Cause:  keyringRefused,
			Reason: "the login keychain refused: " + err.Error(),
		}
	}

	return keyringDiagnosis{
		Cause:  keyringUnattributed,
		Reason: "the OS keyring is unavailable (" + err.Error() + ")",
	}
}
