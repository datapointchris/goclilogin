package goclilogin

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// lockWait bounds how long a process waits for the holder to finish. A refresh
// is one HTTP round trip, so reaching this means the holder is wedged rather
// than busy.
const lockWait = 10 * time.Second

// lockPoll is how often a waiter retries. Short enough that the common case — a
// holder finishing in well under a second — is not padded by it.
const lockPoll = 20 * time.Millisecond

// lockRefresh takes the machine-wide refresh lock for clientID and returns the
// release. The lock lives on an open file descriptor, so the kernel drops it if
// the process dies and a crash never leaves a lock file blocking the next run.
//
// Every failure degrades to an unlocked refresh rather than to an unusable CLI:
// no state directory, an unwritable one, or a holder still wedged after
// lockWait. Unlocked is what the lock replaces, so falling back costs nothing
// that was not already being paid, whereas blocking forever on a wedged peer
// would be a worse failure than the race being prevented.
func lockRefresh(dir, clientID string) func() {
	noop := func() {}
	if dir == "" {
		return noop
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return noop
	}

	lock := flock.New(filepath.Join(dir, clientID+".refresh.lock"))
	ctx, cancel := context.WithTimeout(context.Background(), lockWait)
	defer cancel()

	locked, err := lock.TryLockContext(ctx, lockPoll)
	if err != nil || !locked {
		_ = lock.Close()
		return noop
	}
	return func() { _ = lock.Unlock() }
}
