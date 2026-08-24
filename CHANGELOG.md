# Changelog

Hand-written, for a consumer deciding whether a version matters to them. Entries
say what changed in the API and why it is worth acting on, which generated
commit subjects cannot.

## [Unreleased]

## [0.2.0] — 2026-08-24

### Added

A mode-600 file fallback for hosts with no OS keyring — WSL, containers, headless
servers. On Linux the keychain is the Secret Service over D-Bus, and `go-keyring`
fails there before any request is made. Refusing to store a token would make a
CLI unusable on exactly the machines whose only other route is a browser they do
not have.

`Backend` names where a token went or came from, and `TokenStore.FilePath`
reports the fallback file so a caller told the token went there can name it.

### Changed — all three are breaking

`TokenStore.Save` returns `(Backend, error)`. A downgrade from keychain to
plaintext is reported at the moment it happens rather than swallowed, which is
the whole point of having two stores.

`TokenStore.Load` returns `(*oauth2.Token, Backend, error)` and reads the file
when the keyring holds nothing. It still prefers the keyring whenever that holds
a token, so a host that gains a provider later moves onto it with no re-login.
When neither store has one and the keyring failed for a reason other than an
absent entry, that reason is carried through the error — "not logged in" and
"your keychain is locked" need different fixes.

`NewTokenStore` and `NewTestTokenStore` take a `Config` rather than a service
string, because the store now needs the state directory as well as the keyring
namespace. `Config.LockDir` is renamed `StateDir` and holds both the refresh lock
and the fallback token file; both are state this tool writes, so they live
together.

`TokenStore.Delete` now clears both stores rather than the first that answers. A
token written to the file before that host had a keyring would otherwise survive
the logout meant to remove it.

### Notes for consumers

Migrating from 0.1.0 is four call sites: `NewTokenStore(cfg)`, discard or use the
`Backend` from `Save`, discard or use the `Backend` from `Load`, and rename the
`LockDir` field. Nothing about the on-keychain format changed, so no re-login.

Reproduce the keyringless case from any machine:
`GOOS=linux go build -o /tmp/<cli> . && docker run --rm -v /tmp:/w ubuntu:24.04 /w/<cli> auth status`

## [0.1.0] — 2026-08-24

### Added

The package itself. `Login` runs the OAuth 2.0 device authorization grant,
`TokenStore` persists the result in the OS keychain, and `TokenSource` returns
an auto-refreshing source that serializes its refresh across every process on
the machine.

`VerifySession` reports whether the provider will honor the stored session —
`SessionLive`, `SessionRejected` or `SessionUnverified`. A status command that
reads only the local expiry cannot tell a soft expiry from a revoked grant, and
will promise a refresh that never happens.

`IsSessionRejected` classifies an arbitrary error as the provider refusing a
refresh. A refresh runs inside the transport of whichever request triggered it,
so the refusal arrives as that request's error rather than as anything a command
would recognize.

`NewTestTokenStore` backs a store with an in-memory map, so a consumer's tests
never write to the real keychain.

### Notes for consumers

The lock lives at `<LockDir>/<ClientID>.refresh.lock`, and `LockDir` defaults to
`StateDir(KeyringService)`. A consumer already writing a lock elsewhere should
pass `LockDir` explicitly rather than let the default move it, because two
versions using different paths do not exclude each other during an upgrade.

`Login` takes a `func(DevicePrompt)` rather than writing to a writer itself, so
presentation stays with the CLI. `WriteInstructions` is the conventional
rendering for callers that want it, and it writes to the writer passed in —
stderr, so a command printing a token to stdout stays pipeable.
