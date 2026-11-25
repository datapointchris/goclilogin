package goclilogin

import (
	"fmt"
	"os"
	"sync"

	"github.com/pkg/browser"
)

// browserStreams guards pkg/browser's package-wide Stdout and Stderr, which
// OpenBrowser swaps for the length of one launch.
var browserStreams sync.Mutex

// OpenBrowser opens url in the user's browser, with the launcher's output sent
// to the null device. A browser's startup noise then never lands in the middle
// of the code and URL that WriteInstructions printed. Call it from the func
// handed to Login, on DevicePrompt.BrowserURL. An error is normal over SSH or on
// a host with no browser, and the login goes on, because the code is still on
// the screen.
//
// The output goes to an opened os.DevNull rather than io.Discard. os/exec hands
// a file to the launcher as a descriptor, and gives any other writer a pipe. Wait
// then blocks until every process holding the pipe's write end exits, and a
// browser that xdg-open starts cold holds it. With io.Discard this would return
// only once that browser exits, and Login's poll would wait on it.
func OpenBrowser(url string) error {
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s for the browser's output: %w", os.DevNull, err)
	}
	defer func() { _ = quiet.Close() }()

	browserStreams.Lock()
	defer browserStreams.Unlock()
	stdout, stderr := browser.Stdout, browser.Stderr
	browser.Stdout, browser.Stderr = quiet, quiet
	defer func() { browser.Stdout, browser.Stderr = stdout, stderr }()
	return browser.OpenURL(url)
}
