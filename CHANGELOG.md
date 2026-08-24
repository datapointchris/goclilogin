# Changelog

Hand-written, for a consumer deciding whether a version matters to them. Entries
say what changed in the API and why it is worth acting on, which generated
commit subjects cannot.

## [Unreleased]

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
