# goclilogin — Claude Code instructions

A public Go library, not a CLI. There is no `main` package and nothing to
install; it ships as git tags. Its consumers are product CLIs, each the
command-line client of one web API, kept in a `cli/` module beside that API.

Written to be used by strangers. Treat the exported API, the README and the
godoc as the product — a change that suits the internal consumers is not
automatically right.

## Layout

| Path | Holds |
| --- | --- |
| `doc.go` | Package doc: why the device grant, why refresh is serialized |
| `config.go` | `Config`, `DefaultScopes`, `ClientID`, `StateDir` |
| `deployment.go` | The config file: `LoadDeployment`, `DeploymentForLogin` with RFC 9728 discovery, `Save`, `WriteDeployment` |
| `login.go` | Discovery, the device grant, `DevicePrompt`, `WriteInstructions` |
| `store.go` | `TokenStore` over both backends, `Backend`, `ErrNotLoggedIn` |
| `filestore.go` | The mode-600 fallback for hosts with no keyring |
| `memorykeyring.go` | The in-memory backend behind `NewTestTokenStore` |
| `lock.go` | The machine-wide refresh lock |
| `tokensource.go` | `TokenSource`, `VerifySession`, `IsSessionRejected` |
| `clientcredentials.go` | `ServiceClient` and `ClientCredentialsTokenSource`, for a CLI run by a service |

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
- **The keyring downgrade stays visible.** `Save` returns the `Backend` it used,
  `Load` reports where the token came from, and `Delete` clears both stores.
  There is not always a keyring, so a fallback is needed, and a token that lands
  in plaintext without the user being told is a secret stored where nobody chose
  to put it. Any tool keeping a token in the OS keychain owes the same, whatever
  the token's type. Never let `Save` swallow a
  fall back to plaintext, and never let `Delete` stop at the first store that
  answers: a file token written before that host had a keyring would outlive the
  logout meant to remove it.
- **The fallback is for a host that may have no keyring, not for a keyring that
  refused.** `Save` returns an error where `diag.Cause.keyringPresent()`, because
  a locked keychain is a condition of the session while a file token outlives it
  — `Load` prefers the keyring only while the keyring holds something, so the
  plaintext copy goes on being used after the lock is gone. `keyringUnattributed`
  is the only cause that reaches the file, and a Secret Service error stays
  unattributed on purpose: refusing there would strand the hosts the fallback was
  built for.
- **A keyring that fails is not a keyring with no entry.** `Load` carries the
  provider's own error through only in the first case. Reporting a locked
  keychain as `ErrNotLoggedIn` sends the user to re-authenticate against a store
  that was never the problem.
- **`SessionUnverified` is never folded into the other two.** An unreachable
  provider proves nothing about the grant, and reporting it as live or rejected
  is the defect `VerifySession` was written to fix. x/oauth2 returns a
  `RetrieveError` for every non-2xx answer, a proxy's 502 page included.
  `IsSessionRejected` therefore needs an OAuth error code on a status that is
  neither a 5xx nor a 429. Matching the type alone sends someone to log in
  again, or to rotate a secret, during an outage.
- **`ClientCredentialsTokenSource` persists nothing and reads no environment.**
  Its tokens live in process memory and are requested again once expired, so a
  service's token never outlives the run that fetched it. The secret is an
  argument and never a config key, because the config file is not a secret
  store.
- **A CLI's deployment is one file, and only login writes it.**
  `LoadDeployment` reads `--api` and `$XDG_CONFIG_HOME/<product>/config.toml`
  and nothing else. It reads no environment variable and holds no compiled-in
  address. A second source is a second place a value can come from unseen.
  `DeploymentForLogin` fills only what the file lacks and refuses a typed value
  that differs from it. `Save` adds missing keys at the top and never rewrites
  one, because a config manager may render the file and stays its authority.
- **A token goes only to an API that names its issuer.** An `--api` differing
  from the file's must list the file's issuer in its RFC 9728 metadata, or
  `LoadDeployment` refuses before any request carries a token. The flag stays
  usable for a development API trusting the same login server.
- **Login never writes through a symlink.** A link means a config manager owns
  the file, and its source may be shared by every machine. A client id written
  there becomes every machine's, which ends one client per machine.
  `DeploymentForLogin` refuses the link before the grant whenever `Save` would
  write, and the refusal offers `api` and `issuer` as lines for the source but
  never `client_id`.
- **A login waiting for approval outlives a rate limit.** x/oauth2's poll
  returns on every answer but `authorization_pending` and `slow_down`, so
  `pollForApproval` polls through a client that turns a 429 or
  `temporarily_unavailable` into `slow_down`. Without it, a rate limit on the
  token endpoint ends a login the user is still approving.
- **Presentation stays with the caller.** `Login` takes a `func(DevicePrompt)`;
  it never writes to a stream itself. `WriteInstructions` is offered, not
  imposed.
- **No cobra, and no CLI framework, in this module.** The consumers' auth
  commands have diverged and are deliberately not shared yet — see below. If a
  `cobracmd/` is ever added, cobra stays confined to it, so a consumer importing
  only the core never has cobra in its tree.
- **No state directory means the store refuses rather than improvising.** There
  is then no private place for a secret, and dropping one into a shared temp
  directory is worse than failing.
- **Each dependency earns its place**: `x/oauth2` for the protocol,
  `go-keyring` for the OS keychain, `gofrs/flock` for cross-platform locking,
  `BurntSushi/toml` for the config file. This is the credential path, so an
  addition here is classified by what it can reach, and what was accepted is
  written down, as the next rule does for `BurntSushi/toml`. Nothing is waved
  through.
- **`BurntSushi/toml` reaches only the bytes handed to `toml.Decode` and
  `toml.Marshal`.** It has no network code and no dependencies of its own. It
  gives a correct parser for a file people edit by hand, where a hand-rolled
  subset would reject valid TOML such as a literal string. If it egressed, the
  most it holds is three public addresses and a client name — never a token or
  a secret.
- **Linux, macOS and Windows all build.** `gofrs/flock` is what buys Windows;
  a hand-rolled `unix.Flock` would not. Check with `GOOS=windows go build ./...`
  before claiming otherwise.

## Why the command layer is not in here

The consumers' `internal/cli/auth.go` files have diverged, each in its own
direction. Sharing them would mean a `cobracmd` that every consumer overrides,
which is worse than a small copy in each.

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

## Never write the breaking-change trailer in a commit message

Those two words anywhere in a message cut a major here, and a major on a Go module
with no `/vN` path is an outage rather than a version: `go install ...@latest` stops
seeing the tag, every installed binary is stranded, and recovery is a reinstall on
each machine. The analyzer matches unanchored and ORs past `.semrelrc`, so nothing
switches it off, and a commit that merely *discusses* the trailer cuts one too — say
"that marker" instead. Deliberate majors are `chore(release-major)`.

Recovery is not a history rewrite. Delete the major's releases and tags, remote
and local. Then tag a baseline on `main` above the offending commit and push it;
without the baseline the commit stays in the analyzed range and the next push
cuts the major again. `go list -m github.com/datapointchris/goclilogin@latest`
must then answer the earlier line's tag.
