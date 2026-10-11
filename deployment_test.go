package goclilogin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// configHome points ConfigPath at a fresh directory for one test.
func configHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func writeConfig(t *testing.T, product, content string) string {
	t.Helper()
	path := ConfigPath(product)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// serveMetadata stands up an API serving RFC 9728 metadata. document receives
// the server's own URL, and a nil document is a 404.
func serveMetadata(t *testing.T, document func(base string) *protectedResourceMetadata) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := document(server.URL)
		if r.URL.Path != "/.well-known/oauth-protected-resource" || doc == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestLoadDeployment_ReadsTheFileAndTheAPIFlagOutranksIt(t *testing.T) {
	configHome(t)
	path := writeConfig(t, "myapp", `# rendered by the machine's config manager
api = "https://myapp.example.com"
issuer = "https://auth.example.com"
client_id = "myapp-cli-workstation"
theme = "dark"

[output]
color = true
`)

	got, err := LoadDeployment("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	want := Deployment{
		Path:     path,
		API:      Setting{Value: "https://myapp.example.com", Source: SourceFile, From: path},
		Issuer:   Setting{Value: "https://auth.example.com", Source: SourceFile, From: path},
		ClientID: Setting{Value: "myapp-cli-workstation", Source: SourceFile, From: path},
	}
	if got != want {
		t.Errorf("from the file:\n got %+v\nwant %+v", got, want)
	}

	got, err = LoadDeployment("myapp", "https://staging.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	want.API = Setting{Value: "https://staging.example.com", Source: SourceCommandLine}
	if got != want {
		t.Errorf("with --api:\n got %+v\nwant %+v", got, want)
	}
}

func TestLoadDeployment_AMissingValueNamesTheLoginCommand(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		wantMissing string
		wantAPI     string
	}{
		{name: "no file", wantMissing: "sets no api or issuer or client_id"},
		{
			name:        "a file naming only the API",
			file:        `api = "https://myapp.example.com"`,
			wantMissing: "sets no issuer or client_id",
			wantAPI:     "https://myapp.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configHome(t)
			if tt.file != "" {
				writeConfig(t, "myapp", tt.file)
			}

			got, err := LoadDeployment("myapp", "")
			if !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("err = %v, want ErrNotConfigured", err)
			}
			for _, want := range []string{tt.wantMissing, ConfigPath("myapp"), "run `myapp auth login <url>`"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if got.Path != ConfigPath("myapp") || got.API.Value != tt.wantAPI {
				t.Errorf("partial deployment = %+v, want the path and the api %q", got, tt.wantAPI)
			}
		})
	}
}

func TestDeploymentForLogin_FillsABareFileThatSaveThenServes(t *testing.T) {
	configHome(t)
	api := serveMetadata(t, func(base string) *protectedResourceMetadata {
		return &protectedResourceMetadata{Resource: base, AuthorizationServers: []string{"https://auth.example.com"}}
	})

	got, err := DeploymentForLogin(t.Context(), "myapp", api.URL+"/", "")
	if err != nil {
		t.Fatal(err)
	}
	want := Deployment{
		Path: ConfigPath("myapp"),
		API:  Setting{Value: api.URL, Source: SourceCommandLine},
		Issuer: Setting{
			Value:  "https://auth.example.com",
			Source: SourceDiscovered,
			From:   api.URL + "/.well-known/oauth-protected-resource",
		},
		ClientID: Setting{Value: ClientID("myapp"), Source: SourceHostname, From: shortHostname()},
	}
	if got != want {
		t.Fatalf("login resolved\n got %+v\nwant %+v", got, want)
	}

	if err := got.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeployment("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Setting{"api": loaded.API, "issuer": loaded.Issuer, "client_id": loaded.ClientID} {
		if s.Source != SourceFile {
			t.Errorf("%s came from %q after Save, want the file", name, s.Source)
		}
	}
	if loaded.API.Value != want.API.Value || loaded.Issuer.Value != want.Issuer.Value ||
		loaded.ClientID.Value != want.ClientID.Value {
		t.Errorf("after Save the file holds %+v, want the values login resolved", loaded)
	}
}

// A machine whose config manager rendered all three keys logs in with exactly
// what was rendered: nothing is fetched, and the file is not rewritten.
func TestDeploymentForLogin_ACompleteFileIsUsedAsItIs(t *testing.T) {
	configHome(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("login fetched %s although the file names the issuer", r.URL)
	}))
	t.Cleanup(api.Close)
	content := "api = \"" + api.URL + "\"\nissuer = \"https://auth.example.com\"\nclient_id = \"myapp-cli-workstation\"\n"
	path := writeConfig(t, "myapp", content)

	got, err := DeploymentForLogin(t.Context(), "myapp", api.URL, "myapp-cli-workstation")
	if err != nil {
		t.Fatal(err)
	}
	if got.API.Source != SourceFile || got.Issuer.Source != SourceFile || got.ClientID.Source != SourceFile {
		t.Errorf("login resolved %+v, want every value from the file", got)
	}
	if err := got.Save(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != content {
		t.Errorf("Save rewrote a complete file:\n%s", after)
	}
}

func TestDeploymentForLogin_RefusesAValueTheFileAlreadySets(t *testing.T) {
	tests := []struct {
		name     string
		api      string
		clientID string
		want     string
	}{
		{name: "another API", api: "https://staging.example.com", want: `already sets api = "https://myapp.example.com"`},
		{name: "another client", clientID: "myapp-cli-laptop", want: `already sets client_id = "myapp-cli-workstation"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configHome(t)
			path := writeConfig(t, "myapp", `api = "https://myapp.example.com"
issuer = "https://auth.example.com"
client_id = "myapp-cli-workstation"
`)
			_, err := DeploymentForLogin(t.Context(), "myapp", tt.api, tt.clientID)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), path) {
				t.Errorf("err = %v, want one naming %s and containing %q", err, path, tt.want)
			}
		})
	}
}

func TestDeploymentForLogin_RefusesMetadataItCannotTrust(t *testing.T) {
	tests := []struct {
		name     string
		document func(base string) *protectedResourceMetadata
		want     string
	}{
		{
			name: "metadata describing another resource",
			document: func(string) *protectedResourceMetadata {
				return &protectedResourceMetadata{
					Resource:             "https://elsewhere.example.com",
					AuthorizationServers: []string{"https://auth.example.com"},
				}
			},
			want: "RFC 9728 § 3.3",
		},
		{
			name: "no authorization server",
			document: func(base string) *protectedResourceMetadata {
				return &protectedResourceMetadata{Resource: base}
			},
			want: "names no authorization server",
		},
		{
			name: "two authorization servers",
			document: func(base string) *protectedResourceMetadata {
				return &protectedResourceMetadata{
					Resource:             base,
					AuthorizationServers: []string{"https://a.example.com", "https://b.example.com"},
				}
			},
			want: "names 2 authorization servers",
		},
		{
			name:     "no metadata published",
			document: func(string) *protectedResourceMetadata { return nil },
			want:     "404 Not Found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configHome(t)
			api := serveMetadata(t, tt.document)
			_, err := DeploymentForLogin(t.Context(), "myapp", api.URL, "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestProtectedResourceMetadataURL_GoesBetweenTheHostAndThePath(t *testing.T) {
	tests := map[string]string{
		"https://api.example.com":   "https://api.example.com/.well-known/oauth-protected-resource",
		"https://example.com/myapp": "https://example.com/.well-known/oauth-protected-resource/myapp",
	}
	for resource, want := range tests {
		got, err := protectedResourceMetadataURL(resource)
		if err != nil || got != want {
			t.Errorf("protectedResourceMetadataURL(%q) = %q, %v; want %q", resource, got, err, want)
		}
	}
}

// The issuer below was written to the file while the login waited for
// approval, so it stands, and writing the discovered one too would leave the
// file with a duplicate key that no TOML reader accepts.
func TestSave_AddsOnlyWhatTheFileStillLacks(t *testing.T) {
	configHome(t)
	path := writeConfig(t, "myapp", `# written by hand
api = "https://myapp.example.com"
issuer = "https://written-meanwhile.example.com"

[output]
color = true
`)
	d := Deployment{
		Path:     path,
		API:      Setting{Value: "https://myapp.example.com", Source: SourceFile, From: path},
		Issuer:   Setting{Value: "https://auth.example.com", Source: SourceDiscovered, From: "x"},
		ClientID: Setting{Value: "myapp-cli-workstation", Source: SourceHostname, From: "workstation"},
	}
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		API      string `toml:"api"`
		Issuer   string `toml:"issuer"`
		ClientID string `toml:"client_id"`
		Output   struct {
			Color bool `toml:"color"`
		} `toml:"output"`
	}
	if _, err := toml.Decode(string(content), &file); err != nil {
		t.Fatalf("Save left a file TOML cannot read: %v\n%s", err, content)
	}
	if file.API != "https://myapp.example.com" || file.Issuer != "https://written-meanwhile.example.com" ||
		file.ClientID != "myapp-cli-workstation" || !file.Output.Color {
		t.Errorf("after Save the file reads %+v\n%s", file, content)
	}
	if !strings.Contains(string(content), "# written by hand") {
		t.Errorf("Save dropped the file's comment:\n%s", content)
	}
}

// A config manager that links the file in from its own tree keeps managing it
// after a login writes to it.
func TestSave_WritesThroughASymlink(t *testing.T) {
	configHome(t)
	target := filepath.Join(t.TempDir(), "rendered.toml")
	if err := os.WriteFile(target, []byte("theme = \"dark\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := ConfigPath("myapp")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	d := Deployment{
		Path:     link,
		API:      Setting{Value: "https://myapp.example.com", Source: SourceCommandLine},
		Issuer:   Setting{Value: "https://auth.example.com", Source: SourceDiscovered},
		ClientID: Setting{Value: "myapp-cli-workstation", Source: SourceHostname},
	}
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the config file is no longer a symlink: %v, %v", info, err)
	}
	if _, err := LoadDeployment("myapp", ""); err != nil {
		t.Errorf("reading through the link after Save: %v", err)
	}
}

func TestWriteDeployment_SaysWhereEachValueCameFrom(t *testing.T) {
	d := Deployment{
		Path: "/home/u/.config/myapp/config.toml",
		API:  Setting{Value: "https://myapp.example.com", Source: SourceCommandLine},
		Issuer: Setting{
			Value:  "https://auth.example.com",
			Source: SourceDiscovered,
			From:   "https://myapp.example.com/.well-known/oauth-protected-resource",
		},
	}
	var out strings.Builder
	WriteDeployment(&out, d)

	for _, want := range []string{
		"(command line)",
		"(discovered at https://myapp.example.com/.well-known/oauth-protected-resource)",
		"client_id  -",
		"(not set)",
		"/home/u/.config/myapp/config.toml",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}
