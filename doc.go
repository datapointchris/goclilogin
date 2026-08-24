// Package goclilogin logs a command-line tool into an OIDC provider and keeps
// the resulting session usable across every invocation on the machine.
//
// The OAuth protocol itself is golang.org/x/oauth2's: the device authorization
// grant, the authorization_pending polling with its slow_down backoff, the
// refresh exchange, and the token model all come from there. What this package
// adds is the lifecycle around it — provider discovery, persistence in the OS
// keychain, and a refresh that is safe when several processes run at once.
//
// # Why the device grant
//
// A loopback redirect needs a browser that can reach a listener on the machine
// running the CLI, which is false over SSH. The device grant moves approval to
// any browser on any device and leaves the CLI polling, so logging in on a
// remote box does not mean physically going to it.
//
// # Why refresh is serialized
//
// Providers that follow RFC 9700 rotate the refresh token on every use and
// revoke the whole authorization grant when a consumed one is presented again,
// which they are required to read as a replay they cannot attribute. Two
// processes refreshing from the same stored token therefore cost the user an
// interactive login rather than a retry: one rotates, the other presents the
// token that rotation consumed, and the provider drops the pair.
//
// Several processes running at once is ordinary rather than exceptional — a
// scheduler that shells out to the same CLI for each of its checks produces it
// every run. TokenSource holds a machine-wide lock for the duration of a
// refresh and re-reads the store once it has the lock, so a process that waited
// uses the winner's token instead of replaying its own. A mutex cannot cover
// this, because the contention is between processes.
package goclilogin
