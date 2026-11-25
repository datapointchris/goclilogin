//go:build !windows

package goclilogin

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A launcher that starts a browser cold exits at once, and the browser it
// started lives on holding the launcher's streams. OpenBrowser has to return
// then, or Login's poll waits until the user closes the browser.
func TestOpenBrowser_ReturnsBeforeTheBrowserItStartedExits(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "browser.pid")
	launcher := fmt.Sprintf("#!/bin/sh\nsleep 30 &\necho $! > '%s'\n", pidFile)
	for _, name := range []string{"xdg-open", "open"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(launcher), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			if browser, err := os.FindProcess(pid); err == nil {
				_ = browser.Kill()
			}
		}
	})

	opened := make(chan error, 1)
	go func() { opened <- OpenBrowser("https://idp.test/device?user_code=ABCD-EFGH") }()
	select {
	case err := <-opened:
		if err != nil {
			t.Fatalf("OpenBrowser: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenBrowser waited on the browser its launcher started")
	}
}
