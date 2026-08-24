# goclilogin — Claude Code instructions

A public Go library, not a CLI. There is no `main` package and nothing to
install; it ships as git tags and is consumed by the product CLIs in
`~/webapps/*/cli/`.

Written to be used by strangers. Treat the exported API, the README and the
godoc as the product — a change that suits the internal consumers is not
automatically right. `go list -m all` from a consumer names them.

## Layout

| Path | Holds |
| --- | --- |
| `doc.go` | Package doc: why the device grant, why refresh is serialized |
| `config.go` | `Config`, `DefaultScopes`, `ClientID`, `StateDir` |
| `login.go` | Discovery, the device grant, `DevicePrompt`, `WriteInstructions` |
| `store.go` | `TokenStore` over the OS keychain, `ErrNotLoggedIn` |
| `memorykeyring.go` | The in-memory backend behind `NewTestTokenStore` |
| `lock.go` | The machine-wide refresh lock |
| `tokensource.go` | `TokenSource`, `VerifySession`, `IsSessionRejected` |

## Constraints that must not regress

- **The refresh holds a machine-wide lock and re-reads the store after taking
  it.** Both halves are load-bearing. The lock alone still lets a waiter replay
  its own stale token once it gets in, and the re-read alone races. This is the
  entire reason the library exists rather than a bare `oauth2.ReuseTokenSource`.
- **`TestTokenSource_WithoutTheLockTheGrantIsRevoked` must keep passing**, and
  it passes by asserting the grant *is* revoked when the lock is absent. It is
  the control for `TestTokenSource_ConcurrentProcessesRefreshOnce`. If the
  unlocked path stops revoking, the locked test has stopped proving anything and
  both need rethinking rather than deleting.
- **Every lock failure degrades to an unlocked refresh, never to an error.**
  Blocking forever on a wedged holder is a worse failure than the race being
  prevented: the race costs one login, the block costs the CLI. `lockWait`
  bounds it at ten seconds, which is far past one HTTP round trip.
- **`SessionUnverified` is never folded into the other two.** An unreachable
  provider proves nothing about the grant, and reporting it as live or rejected
  is the defect `VerifySession` was written to fix.
- **Presentation stays with the caller.** `Login` takes a `func(DevicePrompt)`;
  it never writes to a stream itself. `WriteInstructions` is offered, not
  imposed.
- **No cobra, and no CLI framework, in this module.** The consumers' auth
  commands have diverged and are deliberately not shared yet — see below. If a
  `cobracmd/` is ever added, cobra stays confined to it, per
  `standards/repo-structure.md` § "A library keeps its dependencies off its
  consumers' surface".
- **The dependency list is three and each earns its place**: `x/oauth2` for the
  protocol, `go-keyring` for the OS keychain, `gofrs/flock` for cross-platform
  locking. This is the credential path, so an addition here is weighed against
  `standards/dependencies.md` rather than waved through.
- **Linux, macOS and Windows all build.** `gofrs/flock` is what buys Windows;
  a hand-rolled `unix.Flock` would not. Check with `GOOS=windows go build ./...`
  before claiming otherwise.

## Why the command layer is not in here

The four consumers' `internal/cli/auth.go` files run 167–207 lines and have
already diverged. Sharing them would mean a `cobracmd` that every consumer
overrides, which is worse than four small copies.

The core was extracted because it was measured as identical: three of the four
`internal/auth` packages were 447 lines differing only in one constant, the
import path, and where the comments wrap. That measurement is the bar for
extracting anything else from the consumers — take it when the code is the same,
not when it looks similar.

## What this library deliberately does not do

No ID token verification, no back-channel logout, no DPoP, no mTLS-bound tokens.
The consuming APIs verify tokens server-side against the provider's JWKS, so the
client does not need to.

The trigger to revisit is a requirement for one of those, at which point
[zitadel/oidc](https://github.com/zitadel/oidc) — OpenID Foundation certified,
RFC 8628 on the relying-party side — becomes worth the migration. It has no
token persistence and no cross-process safety, so it would replace `login.go`
and leave everything else standing.
