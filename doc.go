// Package goclilogin logs a command-line tool into an OIDC provider and keeps
// the resulting session usable across every invocation on the machine.
//
// The OAuth protocol itself is golang.org/x/oauth2's: the device authorization
// grant, the authorization_pending polling with its slow_down backoff, the
// refresh exchange, and the token model all come from there. What this package
// adds is the lifecycle around it — the config file saying where the CLI is
// pointed, provider discovery, persistence in the OS keychain, and a refresh
// that is safe when several processes run at once.
//
// # Where the CLI is pointed
//
// A product's config file, $XDG_CONFIG_HOME/<product>/config.toml, holds the
// API's address, the issuer and the client id. LoadDeployment reads it on every
// command, with an explicit --api outranking it, and consults no environment
// variable and no compiled-in address. An --api that differs from the file's
// must name the file's issuer in its RFC 9728 metadata before a token is sent
// to it. Login is the only writer. DeploymentForLogin fills in what the file
// lacks, the issuer from the API's RFC 9728 protected-resource metadata, and
// Deployment.Save adds those keys without rewriting any the file already holds.
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
//
// # When no person is present
//
// A CLI run unattended, by a scheduler for one, has nobody to approve a device
// login. ClientCredentialsTokenSource authenticates a ServiceClient as itself
// instead. A ServiceClient is a confidential client registered for the service
// alone, so the service holds its own identity rather than a person's. The
// client-credentials grant issues no refresh token, so
// ClientCredentialsTokenSource uses neither the keychain nor the lock.
//
// # Every request is bounded
//
// Each request this package makes goes through the *http.Client a context
// carries under oauth2.HTTPClient, where the caller set one. Otherwise it goes
// through a client that gives up after 30 seconds. A provider that accepts the
// connection and never answers then fails the command rather than holding it,
// and the failure classifies as SessionUnverified. A device login still waits
// for approval as long as its context allows, because the bound is per request.
package goclilogin
