# goclilogin

OIDC device-grant login for Go command-line tools. Tokens live in the OS
keychain, and the refresh is serialized across every process on the machine.
The same tools run by a service, with no person to approve a login, use the
client-credentials grant instead.

The OAuth protocol is `golang.org/x/oauth2`'s. The device authorization grant,
the `authorization_pending` polling with its `slow_down` backoff, the refresh
exchange and the token model all come from there. This package adds the
lifecycle around it: the config file saying where the CLI is pointed, provider
discovery, persistence in the OS keychain, and a refresh that survives several
processes running at once. That last one is the reason the package exists.

It is a library with no `main` package.

## Install

```bash
go get github.com/datapointchris/goclilogin@latest   # a tagged module; there is no binary
```

## Starting from scratch

A product CLI called `myapp` wires three commands through the package. A
person runs the first one once. Every other command runs the second. The third
proves the login took.

```go
// `myapp auth login <url>`
deployment, err := goclilogin.DeploymentForLogin(ctx, "myapp", url, clientIDFlag) // fills only what config.toml lacks
goclilogin.WriteDeployment(os.Stderr, deployment) // each value and its source, before the login server hears anything

cfg := goclilogin.Config{
    Issuer:         deployment.Issuer.Value,
    ClientID:       deployment.ClientID.Value,
    KeyringService: "myapp-cli", // namespaces this product's keychain entries
}
store := goclilogin.NewTokenStore(cfg)

ctx, cancel := context.WithTimeout(ctx, 15*time.Minute) // the poll ends on the provider's answer or this deadline
defer cancel()
token, err := goclilogin.Login(ctx, cfg, func(p goclilogin.DevicePrompt) {
    goclilogin.WriteInstructions(os.Stderr, cfg.ClientID, p) // code and URL on stderr, so stdout stays pipeable
    _ = browser.OpenURL(p.BrowserURL())                      // optional; failing to open one is normal over SSH
})
backend, err := store.Save(cfg.ClientID, token) // BackendFile means no keyring: tell the user
err = deployment.Save()                        // only after the grant succeeds; adds missing keys, rewrites none

// every later command
deployment, err = goclilogin.LoadDeployment(ctx, "myapp", apiFlag) // the file, with --api outranking it
// ...cfg and store built from deployment as above
source, err := goclilogin.TokenSource(ctx, cfg, store) // ErrNotLoggedIn where nothing is stored
client := oauth2.NewClient(ctx, source)                // injects and renews the bearer token
// requests go to deployment.API.Value

// `myapp auth status`
state, _ := goclilogin.VerifySession(ctx, cfg, store) // SessionLive: the provider still honors the grant
```

The first run needs three things from outside the CLI:

- The provider advertises a `device_authorization_endpoint` in its OIDC
  discovery document. `Login` refuses before asking for a code where it does
  not.
- The client id is registered at the provider as a public client with no
  secret. It goes in the request body.
- The API serves RFC 9728 protected-resource metadata naming its login server.
  A `config.toml` that already sets `issuer` skips this.

`DeploymentForLogin` refuses a config file reached through a symlink, before
the grant starts. `Deployment.Save` waits for the grant because a login refused
for an unregistered client should leave nothing behind for every later command
to read.

## Which function answers which question

| Ask | Function | Reads |
| --- | --- | --- |
| Where is this CLI pointed | `LoadDeployment`, `WriteDeployment` | the config file, and an `--api`'s RFC 9728 metadata where it differs from the file's |
| What does a first login fill in | `DeploymentForLogin` | the config file, then the API's RFC 9728 metadata for a missing `issuer` |
| How does a person log in | `Login` | the issuer's OIDC discovery document, then the device grant |
| Where did the token go | `TokenStore.Save`, `TokenStore.Load` | the OS keychain, then the mode-600 file in `StateDir` |
| How do requests get a token | `TokenSource` | the store, the discovery document, and the refresh lock |
| Does the provider still honor the session | `VerifySession` | the same as `TokenSource` |
| Was this request's error a refused grant | `IsSessionRejected`, `ClassifySession` | the error's chain |
| How does a service with no person authenticate | `ClientCredentialsTokenSource` | the discovery document and the token endpoint |
| How do I test my commands without the keychain | `NewTestTokenStore` | an in-memory map |

## `LoadDeployment` — one file says where the CLI is pointed, and only login writes it

A product CLI needs three values before it can do anything: the API's address,
the login server that issues its tokens, and the client this machine logs in as.
All three live in `$XDG_CONFIG_HOME/<product>/config.toml`, or
`~/.config/<product>/config.toml` where that variable is unset:

```toml
api = "https://api.example.com"
issuer = "https://auth.example.com"
client_id = "myapp-cli-laptop"
```

Any other key in that file is the product's own, and this package leaves it
alone.

**Every command calls `LoadDeployment`.** An explicit `--api` outranks the file,
and that is the whole precedence. A value the file lacks is `ErrNotConfigured`,
naming `<product> auth login <url>`. The `Deployment` returned beside that error
still carries the path and whatever the file set, so a status command can show
what is missing. No environment variable supplies a value, and no address is
compiled in. An address compiled into a binary points every copy of it at one
deployment, a stranger's included. An environment variable is a second place a
value can come from, and a stale export gives no sign it is there.

**An `--api` that differs from the file's is checked, not trusted.** Every
request to it carries a token the file's issuer signed. So its RFC 9728 metadata
must name that issuer among its authorization servers, or the command is refused
before any token is sent. A local development API trusting the same login server
passes. One trusting another login server, or serving no metadata, does not.

**None of the three values is derived after login.** Every command reads them
from the file and caches them nowhere else. So what the file says is where the
CLI is pointed, and a status command printing the file has printed the whole
answer. The `--api` check reads metadata only to refuse, and keeps none of it.
`TokenSource` does read the issuer's OIDC discovery document on every run, for
the token endpoint.

A key set to `""` is an error naming the file. TOML counts it as defined, so a
login filling it in would write a second definition, and no TOML reader accepts
that.

**`DeploymentForLogin` fills in only what the file lacks.**

- `api` is the URL given to login, where the file has none.
- `issuer` comes from the API's [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)
  protected-resource metadata. The well-known suffix
  `/.well-known/oauth-protected-resource` goes between the API's host and its
  path, as RFC 9728 § 3.1 places it. The document must name exactly one
  authorization server. It is refused unless its `resource` is the URL it was
  fetched for (RFC 9728 § 3.3), so a document served at one address cannot send
  a login to a provider describing another.
- `client_id` is `--client-id` where given, otherwise `ClientID(product)`.

A value the user types that differs from the file's is refused, naming the file
to edit. Login never rewrites a value, because the file may be rendered by a
config manager that remains its authority. A file that already holds all three
is used as it is, with no request made.

Each value is a `Setting` carrying its source: the command line, the file, the
discovered metadata, or the hostname. `WriteDeployment` prints each value beside
that source, and the config file's path below them. Print it before `Login`, so
the login server is on screen before anything is sent to it. A status command
prints the same thing.

`Deployment.Save` adds only the keys still missing, at the top of the file, and
keeps everything already there, comments included. It reads the file again
first, so a key written while the login waited for approval is kept rather than
duplicated.

A config file reached through a symlink is refused before the grant, whenever
`Save` would write to it. The same holds for a symlinked product directory. A
link means a config manager owns the file, and its source may be shared by every
machine it manages. A client id written there would become every machine's, so
one revocation would log them all out. The refusal offers `api` and `issuer` as
lines to add to the source. It says the client id belongs wherever the manager
writes each machine's own values.

## `TokenSource` — the refresh is serialized across every process on the machine

Providers following [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
rotate the refresh token on every use, and revoke the **whole authorization
grant** when a consumed one is presented again. The RFC is explicit that the
server cannot tell an attacker from a racing client, so it revokes and accepts
the cost of one re-login.

Two processes refreshing from the same stored token therefore cost an
interactive login rather than a retry:

```text
  process A ──┐                      A wins:  RT1 → RT2, saved
  process B ──┼── all hold RT1 ────► B, C:    replay RT1
  process C ──┘                               ↓
                                     provider revokes the grant
                                              ↓
                                     RT2 is dead too → log in again
```

Several processes at once is ordinary rather than exceptional. A scheduler that
shells out to the same CLI for each of its checks produces it every run.

`TokenSource` holds an exclusive `flock` for the duration of a refresh and
re-reads the store once it has the lock. A process that waited then uses the
winner's token instead of replaying its own. A mutex cannot cover this, because
the contention is between processes rather than goroutines. The lock is a file
in `StateDir`, held on an open descriptor, so a process that dies releases it.

Every lock failure degrades to an unlocked refresh, never to an error. That
covers no state directory, an unwritable one, and a holder still wedged after
ten seconds. The race costs one login, and blocking on a wedged holder would
cost the CLI.

`TestTokenSource_WithoutTheLockTheGrantIsRevoked` pins the claim. It runs the
same concurrent processes with the lock absent and asserts the grant *is*
revoked.
If the unlocked run ever stops revoking, the locked test has stopped proving
anything.

## `Login` — the device grant, because approval has to work over SSH

A loopback redirect needs a browser that can reach a listener on the machine
running the CLI, which is false over SSH. The device grant moves approval to any
browser on any device and leaves the CLI polling, so logging in on a remote box
does not mean physically going to it.

`Login` takes a `func(DevicePrompt)` and never writes to a stream itself. The
caller owns presentation. `WriteInstructions` is the conventional rendering,
offered rather than imposed.

A login waiting for approval outlives a rate limit on the token endpoint. The
poll is x/oauth2's, which keeps going only on `authorization_pending` and
`slow_down`. An HTTP 429, or the OAuth error `temporarily_unavailable` that
Authelia sends when it rate-limits the endpoint itself, reaches that loop as
`slow_down`. The interval then grows by five seconds for every later poll
(RFC 8628 § 3.5). The poll stops only on the provider's answer or the context
ending, so give `Login` a context with a deadline.

`WriteInstructions` prints `BrowserURL`, the verification URL with the code
already in it wherever the provider sends one. The bare verification page is not
enough on its own: Authelia takes a browser that is already signed in straight
past it, and there is then nowhere to type the code. The code is printed as well,
to check against the approval screen.

## `VerifySession` — a soft expiry told apart from a revoked grant

A stored token says what the machine holds, not what the provider will honor. A
status command reading only the local expiry will call a dead grant healthy and
promise a refresh that never happens.

`VerifySession` asks for a token the way a resource call does and reports
`SessionLive`, `SessionRejected`, or `SessionUnverified`. It builds a
`TokenSource`, which reads the issuer's discovery document. A live access token
then answers with no further call. An expired one performs the refresh the next
call would have performed anyway. An unreachable provider proves nothing, so it
is its own state rather than being folded into either of the others.

`VerifySession` also reports `SessionUnverified` when nothing is stored. A
status command calls `TokenStore.Load` first and branches on `ErrNotLoggedIn`.

`IsSessionRejected` is the same question asked of an arbitrary error. A refresh
happens inside the transport of whichever request triggered it, so a refusal
reaches a command as that request's error. That error carries a URL and a raw
OAuth description, and names nothing the user can do about it.

`IsSessionRejected` counts only a refusal the provider states: an OAuth error
code, on any answer but a 5xx or a 429. x/oauth2 returns `*oauth2.RetrieveError`
for a proxy's 502 page and for a provider shedding load as well. Neither says
anything about the grant, so both are `SessionUnverified`, and an outage sends
nobody to log in again. `ClassifySession` applies the same reading to a
`Token()` call's result.

## `TokenStore` — the keychain where there is one, a visible fallback where there is not

On Linux the keychain is the Secret Service over D-Bus, which WSL, containers and
headless hosts do not have. `go-keyring` fails there before any request is made,
with `exec: "dbus-launch": executable file not found in $PATH`, naming nothing
the user can act on. Refusing to store a token would make the CLI unusable on
exactly the machines whose only other route is a browser they do not have.

So the store falls back to a mode-600 file in `StateDir`, and **`Save` returns
which backend took it** rather than swallowing it:

```go
backend, err := store.Save(cfg.ClientID, token)
if backend == goclilogin.BackendFile {
    fmt.Fprintf(os.Stderr, "no OS keyring here — token saved to %s\n", store.FilePath())
}
```

A downgrade from keychain to plaintext is reported at the moment it happens.
`Load` prefers the keyring whenever it holds a token, so a host that gains a
provider later moves onto it with no re-login. `Load` reports its backend too,
so a status command can say which one is in play. `Delete` clears both, or a
file token outlives the logout meant to remove it. `Delete` revokes nothing at
the provider. The machine forgets the token.

The fallback is for a host that may have no keyring, not for a keyring having a
bad day. Where one demonstrably exists and still refuses, `Save` returns an error
naming the fix instead of writing plaintext. A macOS login keychain that will not
unlock from an SSH session is the common case, and the error names
`security unlock-keychain`. The lock is a condition of the session, but a token
written to the file outlives it, because `Load` prefers the keyring only while
the keyring holds something. So the plaintext copy would go on being used long
after the reason for it had gone.

Every Mac has a login keychain, which is what makes that attributable: a
`security` failure there refused rather than being absent. A Secret Service error
carries no such guarantee, so it stays unattributed and keeps the fallback.

When nothing is stored anywhere *and* the keyring failed for a reason other than
an absent entry, that reason is carried in the error's text. The error still
matches `ErrNotLoggedIn`. "Not logged in" and "your keychain is locked" need
different fixes, and a bare `ErrNotLoggedIn` sends the user to re-authenticate
against a store that was never the problem.

The fallback is a Unix concern in practice. Windows uses `wincred`, which is
always present, and it has no POSIX mode bits: `os.Chmod` there toggles only the
read-only flag. If the fallback ever does run on Windows, the file's protection
is whatever ACL the user's profile directory carries, not `0600`.

## `ClientCredentialsTokenSource` — a service authenticates as itself, never as a person

A scheduler running the CLI unattended has no person to approve a device login.
Borrowing a person's login makes the service act as them. A confidential client
using the client-credentials grant (RFC 6749 § 4.4) is the service's own identity
instead:

```go
deployment, err := goclilogin.LoadDeployment(ctx, "myapp", apiFlag)
secret := os.Getenv("MYAPP_CLIENT_SECRET") // wherever the caller keeps it
source, err := goclilogin.ClientCredentialsTokenSource(ctx, goclilogin.ServiceClient{
    Issuer:   deployment.Issuer.Value,
    ClientID: deployment.ClientID.Value, // myapp-svc-scheduler, from the config file
    Scopes:   []string{"myapp.items.read"},
}, secret)
client := oauth2.NewClient(ctx, source)
```

A service's client id comes from its config file like any other client's. The
secret never goes in that file, which is not a secret store.
`ClientCredentialsTokenSource` takes the secret as an argument and reads no
environment. Where the secret lives, and what the variable is called, is the
CLI's decision, as the client id already is.

`myapp-svc-scheduler` is a confidential client registered at the provider for
the service alone. It is never what `goclilogin.ClientID(product)` returns. That
function names the public device-grant client for one machine, which holds no
secret and cannot use this grant. Registering that id as confidential breaks the
device login on that host.

Give the service's client a name your API can tell from a person's, such as a
`-svc-` prefix. The API then admits it as the service, limited to its scopes,
and never as a user.

`Scopes` is sent as given. An empty list is refused before any request.
Authelia grants only the scopes a request names, so a request naming none would
get a token whose `scp` is empty. `DefaultScopes` does not apply. Its `openid`
and `offline_access` mean nothing to this grant, and Authelia's validator rejects
a client-credentials client holding either.

Tokens live in process memory. A new one is requested once the last expires.
Nothing is written to the keychain or the state directory, and no lock is taken.
The grant issues no refresh token, so there is nothing to store and no rotation
for processes to race on.

The client authenticates with HTTP Basic, which RFC 6749 § 2.3.1 requires every
provider to support. The provider answers a wrong secret with a 401
`invalid_client` and an unheld scope with a 400 `invalid_scope`.
`ClassifySession` reports both as `SessionRejected`. What fixes either is the
secret or the client's registration, not a login.

## `Config` — one product on one machine, logging in to one deployment

| Field | Required | Default |
| --- | --- | --- |
| `Issuer` | yes | — |
| `ClientID` | yes | — |
| `KeyringService` | yes | — |
| `Scopes` | no | `openid`, `profile`, `offline_access` |
| `StateDir` | no | `StateDir(KeyringService)` |

`Issuer` and `ClientID` are the config file's `issuer` and `client_id`, read
through `LoadDeployment`. Tokens are keyed by `ClientID` within
`KeyringService`, so several products and machines sharing a keychain do not
collide.

`StateDir` holds the refresh lock and the fallback token file. Both are state
this tool writes, so they live together. `StateDir(name)` is
`$XDG_STATE_HOME/<name>`, or `~/.local/state/<name>` where that variable is
unset. Where no home directory resolves, it is empty. The fallback file then
refuses rather than dropping a token somewhere shared, and the refresh runs
unlocked.

`ClientID(product)` spells the conventional per-machine id from the hostname's
first label, lowercased: `myapp` on a host reporting `laptop.example.lan` gives
`myapp-cli-laptop`. Login writes it to a config file that names no client. One
client per machine keeps a token revocable on both axes.

`offline_access` is what yields the refresh token. A provider-specific
authorization scope is deliberately not in the default. Authelia's
`bearer.authz`, for one, permits only `authorization_code`, `refresh_token` and
`client_credentials` alongside it, which rules out the device grant entirely.

## `NewTestTokenStore` — a consumer's tests never touch the real keychain

`NewTestTokenStore(cfg)` returns a store whose keyring is an in-memory map, so a
consumer can test its own command wiring without writing to the real keychain.
The keychain is shared machine state and a test must not touch it. Point
`cfg.StateDir` at a `t.TempDir()` so the fallback file lands there too.

`LoadDeployment` reads `$XDG_CONFIG_HOME`, so `t.Setenv("XDG_CONFIG_HOME",
t.TempDir())` gives a test a config file of its own.

## Linux, macOS and Windows all build and pass the tests

Locking is [`gofrs/flock`](https://github.com/gofrs/flock), which uses
`LockFileEx` on Windows and `flock` on Linux and macOS. Releases are cut only
from a commit that builds, vets and passes `go test -race` on all three.

## What it deliberately does not do

It is not a general OIDC client. It has no ID token verification, no
back-channel logout, no DPoP and no mTLS-bound tokens. A CLI whose API verifies
tokens server-side against the provider's JWKS does not need those. One that
does need them wants [zitadel/oidc](https://github.com/zitadel/oidc) instead.

It ships no command layer and imports no CLI framework. Each consumer's `auth`
commands are its own, built on the functions above.
