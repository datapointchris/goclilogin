# goclilogin

OIDC device-grant login for Go command-line tools. Tokens live in the OS
keychain, and the refresh is serialized across every process on the machine.
The same tools run by a service, with no person to approve a login, use the
client-credentials grant instead.

```go
// `myapp auth login [url]`, once, interactively. It fills in whatever
// ~/.config/myapp/config.toml lacks, and prints each value and where it came
// from before anything is sent to the login server.
deployment, err := goclilogin.DeploymentForLogin(ctx, "myapp", url, clientIDFlag)
goclilogin.WriteDeployment(os.Stderr, deployment)

cfg := goclilogin.Config{
    Issuer:         deployment.Issuer.Value,
    ClientID:       deployment.ClientID.Value,
    KeyringService: "myapp-cli",
}
store := goclilogin.NewTokenStore(cfg)
token, err := goclilogin.Login(ctx, cfg, func(p goclilogin.DevicePrompt) {
    goclilogin.WriteInstructions(os.Stderr, cfg.ClientID, p)
    _ = browser.OpenURL(p.BrowserURL())
})
if err == nil {
    backend, err := store.Save(cfg.ClientID, token)
    // backend says where it went. Report a fall back to the file; a host with
    // no keyring stores the token in plaintext and the user should know.
    err = deployment.Save() // writes only what the file lacked
}

// Then every later command reads the file, and --api outranks it.
deployment, err = goclilogin.LoadDeployment("myapp", apiFlag)
// ...the same cfg and store, built from it, then:
source, err := goclilogin.TokenSource(ctx, cfg, store)
client := oauth2.NewClient(ctx, source)   // injects and renews the bearer token
// and the requests go to deployment.API.Value.
```

## What this is, and what it is not

The OAuth protocol is `golang.org/x/oauth2`'s. The device authorization grant,
the `authorization_pending` polling with its `slow_down` backoff, the refresh
exchange, and the token model all come from there.

What this package adds is the lifecycle around it: the config file saying where
the CLI is pointed, provider discovery, persistence in the OS keychain, and a
refresh that survives several processes running at once. That last one is the
reason the package exists.

It is not a general OIDC client. There is no ID token verification, no
back-channel logout, no DPoP. A CLI whose API verifies tokens server-side
against the provider's JWKS does not need those, and one that does need them
wants [zitadel/oidc](https://github.com/zitadel/oidc) instead.

## One file says where the CLI is pointed

A product CLI needs three values before it can do anything: the API's address,
the login server that issues its tokens, and the client this machine logs in as.
All three live in one file, `$XDG_CONFIG_HOME/<product>/config.toml`:

```toml
api = "https://api.example.com"
issuer = "https://auth.example.com"
client_id = "myapp-cli-workstation"
```

Any other key in that file is the product's own, and this package leaves it
alone.

**Every command calls `LoadDeployment`.** An explicit `--api` outranks the file,
and that is the whole precedence. A value the file lacks is `ErrNotConfigured`,
naming `<product> auth login <url>`. There is no environment variable and no
compiled-in address. An address compiled into a binary points every copy of it
at one deployment, a stranger's included. An environment variable is a second
place a value can come from, and a stale export gives no sign it is there.

**Nothing is derived after login.** Every command reads the file and nothing
else. Nothing is discovered at run time, and nothing is cached anywhere else. So
what the file says is what the CLI does, and a status command printing the file
has printed the whole answer.

**`DeploymentForLogin` fills in only what the file lacks.**

- `api` is the URL given to login, where the file has none.
- `issuer` comes from the API's [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)
  protected-resource metadata, at `<url>/.well-known/oauth-protected-resource`.
  The document must name exactly one authorization server. It is refused unless
  its `resource` is the URL it was fetched for (RFC 9728 § 3.3), so a document
  served at one address cannot send a login to a provider describing another.
- `client_id` is `--client-id` where given, otherwise `ClientID(product)`.

A value the user types that differs from the file's is refused, naming the file
to edit. Login never rewrites a value, because the file may be rendered by a
config manager that remains its authority. A file that already holds all three
is used as it is, with no request made.

`WriteDeployment` prints each value beside where it came from. Print it before
`Login`, so the login server is on screen before anything is sent to it. A
status command prints the same thing, the config file's path included.

`Deployment.Save` writes the filled-in values only once the device grant
succeeds. A login refused for an unregistered client therefore leaves nothing
behind for every later command to read. `Save` adds only the keys still missing,
at the top of the file, and keeps everything already there, comments included. A
config file that is a symlink is written through, and the link stays.

## Why the refresh is serialized

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
re-reads the store once it has the lock, so a process that waited uses the
winner's token instead of replaying its own. A mutex cannot cover this — the
contention is between processes, not goroutines.

`TestTokenSource_WithoutTheLockTheGrantIsRevoked` pins that claim: it runs the
same eight processes with the lock absent and asserts the grant *is* revoked.
If that test stops failing to revoke, the locked test has stopped proving
anything.

## Why the device grant

A loopback redirect needs a browser that can reach a listener on the machine
running the CLI, which is false over SSH. The device grant moves approval to any
browser on any device and leaves the CLI polling, so logging in on a remote box
does not mean physically going to it.

`WriteInstructions` prints `BrowserURL`, the verification URL with the code
already in it wherever the provider sends one. The bare verification page is not
enough on its own: Authelia takes a browser that is already signed in straight
past it, and there is then nowhere to type the code. The code is printed as well,
to check against the approval screen.

## Telling a soft expiry from a revoked grant

A stored token says what the machine holds, not what the provider will honor. A
status command reading only the local expiry will call a dead grant healthy and
promise a refresh that never happens.

`VerifySession` asks for a token the way a resource call does and reports
`SessionLive`, `SessionRejected`, or `SessionUnverified`. A live access token
answers with no network call; an expired one performs the refresh the next call
would have performed anyway, so the answer costs nothing that was not already
due. An unreachable provider proves nothing, which is why it is its own state
rather than being folded into either of the others.

`IsSessionRejected` is the same question asked of an arbitrary error. A refresh
happens inside the transport of whichever request triggered it, so a refusal
reaches a command as that request's error — carrying a URL and a raw OAuth
description, and naming nothing the user can do about it.

`IsSessionRejected` counts only a refusal the provider states: an OAuth error
code, on any answer but a 5xx or a 429. x/oauth2 returns `*oauth2.RetrieveError`
for a proxy's 502 page and for a provider shedding load as well. Neither says
anything about the grant, so both are `SessionUnverified`, and an outage sends
nobody to log in again.

## A service authenticates as itself

A scheduler running the CLI unattended has no person to approve a device login.
Borrowing a person's login makes the service act as them. A confidential client
using the client-credentials grant (RFC 6749 §4.4) is the service's own identity
instead:

```go
deployment, err := goclilogin.LoadDeployment("myapp", apiFlag)
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

`myapp-svc-scheduler` is a confidential client registered at the provider for
the service alone. It is never what `goclilogin.ClientID(product)` returns. That
function names the public device-grant client for one machine, which holds no
secret and cannot use this grant. Registering that id as confidential breaks the
device login on that host.

Give the service's client a name your API can tell from a person's, such as a
`-svc-` prefix. The API then admits it as the service, limited to its scopes,
and never as a user.

`ClientCredentialsTokenSource` takes the secret as an argument and reads no
environment. Where the secret lives, and what the variable is called, is the
CLI's decision, as the client id already is.

`Scopes` is sent as given. An empty list is refused before any request.
Authelia grants only the scopes a request names, so a request naming none would
get a token whose `scp` is empty. `DefaultScopes` does not apply. Its `openid` and
`offline_access` mean nothing to this grant, and Authelia's validator rejects a
client-credentials client holding either.

Tokens live in process memory. A new one is requested once the last expires.
Nothing is written to the keychain or the state directory, and no lock is taken.
The grant issues no refresh token, so there is nothing to store and no rotation
for processes to race on.

The client authenticates with HTTP Basic, which RFC 6749 §2.3.1 requires every
provider to support. The provider answers a wrong secret with a 401
`invalid_client` and an unheld scope with a 400 `invalid_scope`.
`ClassifySession` reports both as `SessionRejected`. What fixes either is the
secret or the client's registration, not a login.

## Configuration

| Field | Required | Default |
| --- | --- | --- |
| `Issuer` | yes | — |
| `ClientID` | yes | — |
| `KeyringService` | yes | — |
| `Scopes` | no | `openid`, `profile`, `offline_access` |
| `StateDir` | no | `StateDir(KeyringService)` |

`Issuer` and `ClientID` are the config file's `issuer` and `client_id`, read
through `LoadDeployment`.

`StateDir` holds the refresh lock and the fallback token file. Both are state
this tool writes, so they live together.

`ClientID(product)` spells the conventional per-machine id — `myapp` on a host
reporting `archlinux.trusted` gives `myapp-cli-archlinux`. Login writes it to a
config file that names no client. One client per machine keeps a token
revocable on both axes.

`offline_access` is what yields the refresh token. A provider-specific
authorization scope is deliberately not in the default: Authelia's
`bearer.authz`, for one, permits only `authorization_code`, `refresh_token` and
`client_credentials` alongside it, which rules out the device grant entirely.

## There is not always a keyring

On Linux the keychain is the Secret Service over D-Bus, which WSL, containers and
headless hosts do not have. `go-keyring` fails there before any request is made,
with `exec: "dbus-launch": executable file not found in $PATH` — naming nothing
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
provider later moves onto it with no re-login, and it reports its backend too so
a status command can say which one is in play. `Delete` clears both, or a file
token outlives the logout meant to remove it.

The fallback is for a host that may have no keyring, not for a keyring having a
bad day. Where one demonstrably exists and still refuses, `Save` returns an error
naming the fix instead of writing plaintext. A macOS login keychain that will not
unlock from an SSH session is the common case: the lock is a condition of the
session and clears with one command, but a token written to the file outlives it,
because `Load` prefers the keyring only while the keyring holds something. So the
plaintext copy would go on being used long after the reason for it had gone.

Every Mac has a login keychain, which is what makes that attributable — a
`security` failure there refused rather than being absent. A Secret Service error
carries no such guarantee, so it stays unattributed and keeps the fallback.

When nothing is stored anywhere *and* the keyring failed for a reason other than
an absent entry, that reason is carried through the error. "Not logged in" and
"your keychain is locked" need different fixes, and a bare `ErrNotLoggedIn`
sends the user to re-authenticate against a store that was never the problem.

This mirrors `standards/infrastructure.md` § "There is not always a keyring, and
the downgrade has to be visible", whose canonical source is `~/tools/ifiles/auth`
— a different token type, the same obligation.

The fallback is a Unix concern in practice. Windows uses `wincred`, which is
always present, and it has no POSIX mode bits — `os.Chmod` there toggles only the
read-only flag. If the fallback ever does run on Windows, the file's protection
is whatever ACL the user's profile directory carries, not `0600`.

## Testing against it

`NewTestTokenStore(cfg)` returns a store whose keyring is an in-memory map, so a
consumer can test its own command wiring without writing to the real keychain.
The keychain is shared machine state and a test must not touch it. Point
`cfg.StateDir` at a `t.TempDir()` so the fallback file lands there too.

`LoadDeployment` reads `$XDG_CONFIG_HOME`, so `t.Setenv("XDG_CONFIG_HOME",
t.TempDir())` gives a test a config file of its own.

## Platforms

Linux, macOS and Windows. Locking is [`gofrs/flock`](https://github.com/gofrs/flock),
which uses `LockFileEx` on Windows and `flock` elsewhere.
