package goclilogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/BurntSushi/toml"
)

// ErrNotConfigured reports a config file that does not yet say where the API
// is, which login server issues its tokens, or which client this machine logs
// in as. The error wrapping it names the file and the login command that fills
// it in.
var ErrNotConfigured = errors.New("not configured")

// Source names the layer that set a Setting.
type Source string

const (
	// SourceCommandLine is a value the user typed: the --api flag, the URL
	// given to login, or login's --client-id.
	SourceCommandLine Source = "command-line"

	// SourceFile is the product's config file. From is its path.
	SourceFile Source = "file"

	// SourceDiscovered is the authorization server the API names in its
	// protected-resource metadata (RFC 9728). From is the URL it was read from.
	SourceDiscovered Source = "discovered"

	// SourceHostname is the per-machine spelling ClientID derives. From is the
	// short hostname it was derived from.
	SourceHostname Source = "hostname"
)

// Setting is one resolved value and the layer that set it. An empty Value
// means nothing set it.
type Setting struct {
	Value  string `json:"value"`
	Source Source `json:"source,omitempty"`
	From   string `json:"from,omitempty"`
}

// Deployment is where a product CLI's API and login server are, and the client
// this machine logs in to them as. It is read from the product's config file,
// which holds the keys api, issuer and client_id.
type Deployment struct {
	// Path is the config file the values were read from and are saved to.
	Path string `json:"config_file"`

	API      Setting `json:"api"`
	Issuer   Setting `json:"issuer"`
	ClientID Setting `json:"client_id"`
}

// configFile is the part of a product's config file this package owns. Any
// other key in the file belongs to the product and is read and kept as it is.
type configFile struct {
	API      string `toml:"api,omitempty"`
	Issuer   string `toml:"issuer,omitempty"`
	ClientID string `toml:"client_id,omitempty"`
}

// protectedResourceMetadata is the part of an RFC 9728 document login reads.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// ConfigPath is a product's config file: $XDG_CONFIG_HOME/<product>/config.toml,
// falling back to ~/.config/<product>/config.toml. It returns "" when no home
// directory resolves, and every function reading the file then refuses.
func ConfigPath(product string) string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, product, "config.toml")
}

// LoadDeployment reads the deployment every command of a product CLI talks to.
// api is the --api flag's value, and outranks the file's when it is not empty.
//
// Nothing else is consulted: no environment variable and no compiled-in
// address. A value the file lacks is ErrNotConfigured, wrapped with the
// `<product> auth login <url>` command that fills it in. The Deployment
// returned beside that error still carries Path and whatever the file did set,
// so a status command can show what is missing.
//
// An api that differs from the file's is checked rather than trusted, because
// every request to it carries a token the file's issuer signed. Its RFC 9728
// metadata must name that issuer among its authorization servers, or the
// command is refused before any token is sent. Nothing the check reads is kept.
func LoadDeployment(ctx context.Context, product, api string) (Deployment, error) {
	path := ConfigPath(product)
	file, err := readConfigFile(path)
	if err != nil {
		return Deployment{Path: path}, err
	}
	d := Deployment{
		Path:     path,
		API:      fromFile(file.API, path),
		Issuer:   fromFile(file.Issuer, path),
		ClientID: fromFile(file.ClientID, path),
	}
	if api != "" {
		d.API = Setting{Value: api, Source: SourceCommandLine}
	}

	var missing []string
	for _, key := range []struct {
		name string
		set  Setting
	}{{"api", d.API}, {"issuer", d.Issuer}, {"client_id", d.ClientID}} {
		if key.set.Value == "" {
			missing = append(missing, key.name)
		}
	}
	if len(missing) > 0 {
		return d, fmt.Errorf("%w: %s sets no %s; run `%s auth login <url>`",
			ErrNotConfigured, path, strings.Join(missing, " or "), product)
	}

	if d.API.Value, err = normalizeAPI(d.API.Value); err != nil {
		return d, describeAPIError(err, d.API)
	}
	if d.API.Source == SourceCommandLine {
		fileAPI, _ := normalizeAPI(file.API)
		if d.API.Value != fileAPI {
			if err := requireTrustedIssuer(ctx, d.API.Value, d.Issuer.Value, path); err != nil {
				return d, err
			}
		}
	}
	return d, nil
}

// requireTrustedIssuer refuses an API whose RFC 9728 metadata does not name
// issuer among its authorization servers. A token issuer signed is sent with
// every request to that API, so an API trusting another login server would
// receive a token it cannot use and could replay.
func requireTrustedIssuer(ctx context.Context, resource, issuer, path string) error {
	meta, metadataURL, err := readProtectedResourceMetadata(ctx, resource)
	if err != nil {
		return fmt.Errorf("check --api %s before sending it a token: %w", resource, err)
	}
	for _, server := range meta.AuthorizationServers {
		if server == issuer {
			return nil
		}
	}
	named := "no login server"
	if len(meta.AuthorizationServers) > 0 {
		named = strings.Join(meta.AuthorizationServers, ", ") + " as its login server"
	}
	return fmt.Errorf("%s names %s, not %s from %s; no token is sent to it",
		metadataURL, named, issuer, path)
}

// DeploymentForLogin resolves the deployment a login authenticates against. It
// fills in only what the config file lacks:
//
//   - api is the file's, or else api, the URL the user gave login.
//   - issuer is the file's, or else the one authorization server the API names
//     in its RFC 9728 metadata. That document's URL puts
//     /.well-known/oauth-protected-resource between the API's host and its
//     path, as RFC 9728 § 3.1 places it. The document is refused unless its
//     resource is the API it was fetched for (RFC 9728 § 3.3).
//   - client_id is the file's, or else clientID from --client-id, or else
//     ClientID(product).
//
// A value the user typed that differs from the file's is refused, naming the
// file to edit, because login never rewrites what the file says. A file reached
// through a symlink is refused whenever Save would write to it, so the refusal
// comes before the user approves a grant rather than after. Print the result
// before the device grant starts, so the login server is on screen before
// anything is sent to it, and Save it once the grant succeeds.
func DeploymentForLogin(ctx context.Context, product, api, clientID string) (Deployment, error) {
	path := ConfigPath(product)
	file, err := readConfigFile(path)
	if err != nil {
		return Deployment{}, err
	}
	d := Deployment{Path: path}

	switch {
	case file.API != "":
		d.API = fromFile(file.API, path)
		if d.API.Value, err = normalizeAPI(file.API); err != nil {
			return Deployment{}, describeAPIError(err, d.API)
		}
		if api != "" {
			given, err := normalizeAPI(api)
			if err != nil {
				return Deployment{}, err
			}
			if given != d.API.Value {
				return Deployment{}, fmt.Errorf("%s already sets api = %q; edit it there to log in to %s",
					path, d.API.Value, given)
			}
		}
	case api != "":
		given, err := normalizeAPI(api)
		if err != nil {
			return Deployment{}, err
		}
		d.API = Setting{Value: given, Source: SourceCommandLine}
	default:
		return Deployment{}, fmt.Errorf("%w: %s sets no api; run `%s auth login <url>`",
			ErrNotConfigured, path, product)
	}

	if file.Issuer != "" {
		d.Issuer = fromFile(file.Issuer, path)
	} else {
		issuer, metadataURL, err := discoverAuthorizationServer(ctx, d.API.Value, path)
		if err != nil {
			return Deployment{}, err
		}
		d.Issuer = Setting{Value: issuer, Source: SourceDiscovered, From: metadataURL}
	}

	switch {
	case file.ClientID != "":
		if clientID != "" && clientID != file.ClientID {
			return Deployment{}, fmt.Errorf("%s already sets client_id = %q; edit it there to log in as %s",
				path, file.ClientID, clientID)
		}
		d.ClientID = fromFile(file.ClientID, path)
	case clientID != "":
		d.ClientID = Setting{Value: clientID, Source: SourceCommandLine}
	default:
		d.ClientID = Setting{Value: ClientID(product), Source: SourceHostname, From: shortHostname()}
	}

	if missing := d.unsaved(file); missing != (configFile{}) {
		if link := symlinkOnPath(path); link != "" {
			return Deployment{}, refuseLink(link, path, missing)
		}
	}
	return d, nil
}

// Save writes every value that did not come from the config file into it, so
// every later command reads it there. A file that lacks nothing is not touched.
//
// Nothing already in the file is rewritten. The file is read again first, so
// a key written while the login waited for approval is kept rather than
// duplicated. The keys still missing go at the top of the file, where TOML
// reads them as top-level keys whatever tables follow.
//
// A config file reached through a symlink is refused, as DeploymentForLogin
// refuses it before the grant. A link created while the login waited is the
// case left for Save.
func (d Deployment) Save() error {
	if d.Path == "" {
		return errors.New("no config file to save to: neither XDG_CONFIG_HOME nor a home directory is set")
	}
	current, err := readConfigFile(d.Path)
	if err != nil {
		return err
	}
	missing := d.unsaved(current)
	if missing == (configFile{}) {
		return nil
	}
	if link := symlinkOnPath(d.Path); link != "" {
		return refuseLink(link, d.Path, missing)
	}

	keys, err := toml.Marshal(missing)
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(d.Path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	content := keys
	if len(existing) > 0 {
		content = append(append(keys, '\n'), existing...)
	}
	return writeFileAtomically(d.Path, content)
}

// unsaved is what Save writes: each value current lacks that a layer other than
// the config file supplied.
func (d Deployment) unsaved(current configFile) configFile {
	var missing configFile
	if current.API == "" && d.API.Source != SourceFile {
		missing.API = d.API.Value
	}
	if current.Issuer == "" && d.Issuer.Source != SourceFile {
		missing.Issuer = d.Issuer.Value
	}
	if current.ClientID == "" && d.ClientID.Source != SourceFile {
		missing.ClientID = d.ClientID.Value
	}
	return missing
}

// refuseLink is the refusal for a config file reached through link. A link means
// a config manager owns the file, and its source may be shared by every machine
// it manages. So the refusal offers api and issuer as lines for that source, and
// never a client_id: one written there becomes every machine's client id.
func refuseLink(link, path string, missing configFile) error {
	refusal := fmt.Sprintf("%s is a symlink, so whatever manages it owns %s and login does not write through it", link, path)
	if shared := (configFile{API: missing.API, Issuer: missing.Issuer}); shared != (configFile{}) {
		lines, err := toml.Marshal(shared)
		if err != nil {
			return err
		}
		refusal += fmt.Sprintf("; add these lines to its source:\n%s", lines)
	}
	if missing.ClientID != "" {
		refusal += fmt.Sprintf("\nIt sets no client_id. That names one machine, %s here, so set it where the manager writes each machine's own values, never in a source they share.",
			missing.ClientID)
	}
	return errors.New(refusal)
}

// symlinkOnPath returns the config file or the product directory holding it,
// whichever is a symlink, or "" where neither is.
func symlinkOnPath(path string) string {
	for _, candidate := range []string{path, filepath.Dir(path)} {
		if info, err := os.Lstat(candidate); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return candidate
		}
	}
	return ""
}

// WriteDeployment is the conventional rendering of a Deployment: each value,
// the layer that set it, and the config file's path. A login prints it before
// the device grant starts, and a status command prints it as the answer to
// where the CLI is pointed.
func WriteDeployment(w io.Writer, d Deployment) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range []struct {
		key string
		set Setting
	}{{"api", d.API}, {"issuer", d.Issuer}, {"client_id", d.ClientID}} {
		value := row.set.Value
		if value == "" {
			value = "-"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", row.key, value, row.set.describeSource())
	}
	_, _ = fmt.Fprintf(tw, "  config\t%s\t\n", d.Path)
	_ = tw.Flush()
}

// describeSource is the parenthesized origin WriteDeployment prints beside a
// value.
func (s Setting) describeSource() string {
	switch s.Source {
	case SourceCommandLine:
		return "(command line)"
	case SourceFile:
		return "(config file)"
	case SourceDiscovered:
		return "(discovered at " + s.From + ")"
	case SourceHostname:
		if s.From == "" {
			return "(no hostname)"
		}
		return "(from hostname " + s.From + ")"
	}
	return "(not set)"
}

// fromFile is a value the config file set, or an unset Setting where it set
// nothing.
func fromFile(value, path string) Setting {
	if value == "" {
		return Setting{}
	}
	return Setting{Value: value, Source: SourceFile, From: path}
}

// readConfigFile reads the keys this package owns. A file that does not exist
// holds none of them, which is not an error.
//
// A key set to "" is refused rather than read as absent. TOML counts it as
// defined, so a login filling it in would write a second definition, and no
// TOML reader accepts a file holding two.
func readConfigFile(path string) (configFile, error) {
	var file configFile
	if path == "" {
		return file, errors.New("no config file: neither XDG_CONFIG_HOME nor a home directory is set")
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, err
	}
	meta, err := toml.Decode(string(data), &file)
	if err != nil {
		return file, fmt.Errorf("read %s: %w", path, err)
	}
	for _, key := range []struct{ name, value string }{
		{"api", file.API}, {"issuer", file.Issuer}, {"client_id", file.ClientID},
	} {
		if key.value == "" && meta.IsDefined(key.name) {
			return file, fmt.Errorf("%s sets %s to an empty value; give it one, or delete the line for login to fill in",
				path, key.name)
		}
	}
	return file, nil
}

// normalizeAPI checks that raw is an absolute http or https URL and returns it
// without a trailing slash. That is the resource identifier RFC 9728 inserts
// its well-known suffix into and compares the document's resource against.
func normalizeAPI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("api %q is not an http or https URL, such as https://api.example.com", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// describeAPIError names where a malformed api came from.
func describeAPIError(err error, api Setting) error {
	if api.Source == SourceFile {
		return fmt.Errorf("%s: %w", api.From, err)
	}
	return err
}

// protectedResourceMetadataURL inserts RFC 9728's well-known suffix between the
// resource identifier's host and its path, as § 3.1 places it.
func protectedResourceMetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil {
		return "", err
	}
	u.Path = "/.well-known/oauth-protected-resource" + strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// readProtectedResourceMetadata fetches an API's RFC 9728 protected-resource
// metadata and returns it with the URL it was read from. A document describing
// another resource is refused, as § 3.3 requires.
func readProtectedResourceMetadata(ctx context.Context, resource string) (protectedResourceMetadata, string, error) {
	var meta protectedResourceMetadata
	metadataURL, err := protectedResourceMetadataURL(resource)
	if err != nil {
		return meta, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return meta, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return meta, "", fmt.Errorf("reach the API at %s: %w", metadataURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return meta, "", fmt.Errorf("%s returned %s, so the API names no login server", metadataURL, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return meta, "", fmt.Errorf("read %s: %w", metadataURL, err)
	}
	if meta.Resource != resource {
		return meta, "", fmt.Errorf("%s describes %q rather than %q, so it is refused (RFC 9728 § 3.3)",
			metadataURL, meta.Resource, resource)
	}
	return meta, metadataURL, nil
}

// discoverAuthorizationServer reads the issuer an API trusts from its RFC 9728
// protected-resource metadata. It returns the issuer and the URL it read it
// from. path is the config file named in an error the user fixes there.
func discoverAuthorizationServer(ctx context.Context, resource, path string) (string, string, error) {
	meta, metadataURL, err := readProtectedResourceMetadata(ctx, resource)
	if err != nil {
		return "", "", fmt.Errorf("%w; setting issuer in %s skips this lookup", err, path)
	}
	switch len(meta.AuthorizationServers) {
	case 0:
		return "", "", fmt.Errorf("%s names no authorization server; set issuer in %s", metadataURL, path)
	case 1:
		return meta.AuthorizationServers[0], metadataURL, nil
	default:
		return "", "", fmt.Errorf("%s names %d authorization servers (%s); set issuer in %s to choose one",
			metadataURL, len(meta.AuthorizationServers), strings.Join(meta.AuthorizationServers, ", "), path)
	}
}

// writeFileAtomically replaces path with content through a rename, so a reader
// never sees half a file. An existing file keeps its mode; a new one is 0644,
// since the file holds addresses and a client name but never a secret.
func writeFileAtomically(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".config.toml.*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
