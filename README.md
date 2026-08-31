# goclilogin

OIDC device-grant login for Go command-line tools. Tokens live in the OS
keychain, and the refresh is serialized across every process on the machine.

```go
cfg := goclilogin.Config{
    Issuer:         "https://auth.example.com",
    ClientID:       goclilogin.ClientID("myapp"), // myapp-cli-<hostname>
    KeyringService: "myapp-cli",
}
store := goclilogin.NewTokenStore(cfg)

// Log in, once, interactively.
token, err := goclilogin.Login(ctx, cfg, func(p goclilogin.DevicePrompt) {
    goclilogin.WriteInstructions(os.Stderr, cfg.ClientID, p)
    _ = browser.OpenURL(p.BrowserURL())
})
if err == nil {
    backend, err := store.Save(cfg.ClientID, token)
    // backend says where it went. Report a fall back to the file; a host with
    // no keyring stores the token in plaintext and the user should know.
}

// Then, on every later invocation.
source, err := goclilogin.TokenSource(ctx, cfg, store)
client := oauth2.NewClient(ctx, source)   // injects and renews the bearer token
```

## What this is, and what it is not

The OAuth protocol is `golang.org/x/oauth2`'s. The device authorization grant,
the `authorization_pending` polling with its `slow_down` backoff, the refresh
exchange, and the token model all come from there.

What this package adds is the lifecycle around it: provider discovery,
persistence in the OS keychain, and a refresh that survives several processes
running at once. That last one is the reason the package exists.

It is not a general OIDC client. There is no ID token verification, no
back-channel logout, no DPoP. A CLI whose API verifies tokens server-side
against the provider's JWKS does not need those, and one that does need them
wants [zitadel/oidc](https://github.com/zitadel/oidc) instead.

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

## Configuration

| Field | Required | Default |
| --- | --- | --- |
| `Issuer` | yes | — |
| `ClientID` | yes | — |
| `KeyringService` | yes | — |
| `Scopes` | no | `openid`, `profile`, `offline_access` |
| `StateDir` | no | `StateDir(KeyringService)` |

`StateDir` holds the refresh lock and the fallback token file. Both are state
this tool writes, so they live together.

`ClientID(product)` spells the conventional per-machine id — `myapp` on a host
reporting `archlinux.trusted` gives `myapp-cli-archlinux`. One client per
machine keeps a token revocable on both axes.

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

## Platforms

Linux, macOS and Windows. Locking is [`gofrs/flock`](https://github.com/gofrs/flock),
which uses `LockFileEx` on Windows and `flock` elsewhere.
