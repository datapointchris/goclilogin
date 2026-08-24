package goclilogin

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultScopes are what a CLI needs from a standard OIDC provider.
// offline_access yields the refresh token; openid and profile make the access
// token a standard OIDC one.
//
// A provider-specific authorization scope is deliberately absent. Authelia's
// bearer.authz, for one, permits only authorization_code, refresh_token and
// client_credentials alongside it, which rules out the device grant. A caller
// that needs such a scope sets Scopes itself and accepts the consequence.
var DefaultScopes = []string{"openid", "profile", "offline_access"}

// Config is one CLI's view of one deployment. Every field except Scopes and
// LockDir is required; those two have documented defaults.
type Config struct {
	// Issuer is the OIDC provider's base URL. Discovery hangs off it.
	Issuer string

	// ClientID identifies this (product × machine) pair to the provider. One
	// client per machine keeps a token revocable on both axes, and ClientID
	// derives the conventional spelling.
	ClientID string

	// KeyringService namespaces this product's entries in the OS keychain.
	// Tokens are keyed within it by ClientID, so several products and machines
	// sharing a keychain do not collide.
	KeyringService string

	// Scopes requested at login. Empty means DefaultScopes.
	Scopes []string

	// StateDir holds this tool's own mutable state: the refresh lock, and the
	// fallback token file used on hosts with no OS keyring. Empty means
	// StateDir(KeyringService).
	//
	// It is never left unset in a way that skips locking, because an unlocked
	// refresh is the failure this package exists to prevent.
	StateDir string
}

// scopes resolves Scopes against its default.
func (c Config) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return DefaultScopes
}

// stateDir resolves StateDir against its default.
func (c Config) stateDir() string {
	if c.StateDir != "" {
		return c.StateDir
	}
	return StateDir(c.KeyringService)
}

// ClientID spells the conventional per-machine client id for a product:
// product "icb" on a host reporting "archlinux.trusted" gives
// "icb-cli-archlinux". A machine whose hostname differs from its logical name
// overrides the result rather than relying on it.
func ClientID(product string) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return product + "-cli"
	}
	short := strings.ToLower(strings.SplitN(host, ".", 2)[0])
	return product + "-cli-" + short
}

// StateDir resolves a tool's own XDG state directory — $XDG_STATE_HOME/<name>,
// falling back to ~/.local/state/<name>. State is what the tool writes and the
// user does not. Returns "" when no home directory resolves, which callers read
// as "no state directory available" rather than as an error.
func StateDir(name string) string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, name)
}
