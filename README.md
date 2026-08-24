# goclilogin

OIDC device-grant login for Go command-line tools. Tokens live in the OS
keychain, and the refresh is serialized across every process on the machine.

```go
cfg := goclilogin.Config{
    Issuer:         "https://auth.example.com",
    ClientID:       goclilogin.ClientID("myapp"), // myapp-cli-<hostname>
    KeyringService: "myapp-cli",
}
store := goclilogin.NewTokenStore(cfg.KeyringService)

// Log in, once, interactively.
token, err := goclilogin.Login(ctx, cfg, func(p goclilogin.DevicePrompt) {
    goclilogin.WriteInstructions(os.Stderr, cfg.ClientID, p)
    _ = browser.OpenURL(p.BrowserURL())
})
if err == nil {
    err = store.Save(cfg.ClientID, token)
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
| `LockDir` | no | `StateDir(KeyringService)` |

`ClientID(product)` spells the conventional per-machine id — `myapp` on a host
reporting `archlinux.trusted` gives `myapp-cli-archlinux`. One client per
machine keeps a token revocable on both axes.

`offline_access` is what yields the refresh token. A provider-specific
authorization scope is deliberately not in the default: Authelia's
`bearer.authz`, for one, permits only `authorization_code`, `refresh_token` and
`client_credentials` alongside it, which rules out the device grant entirely.

## Testing against it

`NewTestTokenStore(service)` returns a store backed by an in-memory map, so a
consumer can test its own command wiring without writing to the real keychain.
The keychain is shared machine state and a test must not touch it.

## Platforms

Linux, macOS and Windows. Locking is [`gofrs/flock`](https://github.com/gofrs/flock),
which uses `LockFileEx` on Windows and `flock` elsewhere.
