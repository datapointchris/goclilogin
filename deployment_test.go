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

	got, err := LoadDeployment(t.Context(), "myapp", "")
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

	staging := serveMetadata(t, func(base string) *protectedResourceMetadata {
		return &protectedResourceMetadata{Resource: base, AuthorizationServers: []string{"https://auth.example.com"}}
	})
	got, err = LoadDeployment(t.Context(), "myapp", staging.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	want.API = Setting{Value: staging.URL, Source: SourceCommandLine}
	if got != want {
		t.Errorf("with --api:\n got %+v\nwant %+v", got, want)
	}
}

// A command run with --api naming a host other than the file's would send that
// host a token the file's issuer signed. A host trusting another login server
// is refused before any token goes to it.
func TestLoadDeployment_RefusesAnAPIFlagTrustingAnotherLoginServer(t *testing.T) {
	configHome(t)
	writeConfig(t, "myapp", `api = "https://myapp.example.com"
issuer = "https://auth.example.com"
client_id = "myapp-cli-workstation"
`)
	elsewhere := serveMetadata(t, func(base string) *protectedResourceMetadata {
		return &protectedResourceMetadata{Resource: base, AuthorizationServers: []string{"https://auth.elsewhere.example.com"}}
	})

	_, err := LoadDeployment(t.Context(), "myapp", elsewhere.URL)
	if err == nil || !strings.Contains(err.Error(), "no token is sent to it") {
		t.Errorf("err = %v, want a refusal naming the other login server", err)
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

			got, err := LoadDeployment(t.Context(), "myapp", "")
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
	loaded, err := LoadDeployment(t.Context(), "myapp", "")
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

// RFC 9728 § 3.1 puts the well-known suffix between the host and the path, so
// an API served under a path is found at a URL that does not start with its own.
func TestDeploymentForLogin_DiscoversAnAPIServedUnderAPath(t *testing.T) {
	configHome(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource/myapp" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(protectedResourceMetadata{
			Resource:             server.URL + "/myapp",
			AuthorizationServers: []string{"https://auth.example.com"},
		})
	}))
	t.Cleanup(server.Close)

	got, err := DeploymentForLogin(t.Context(), "myapp", server.URL+"/myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	want := Setting{
		Value:  "https://auth.example.com",
		Source: SourceDiscovered,
		From:   server.URL + "/.well-known/oauth-protected-resource/myapp",
	}
	if got.Issuer != want {
		t.Errorf("issuer = %+v, want %+v", got.Issuer, want)
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

// A config.toml deployed as a symlink into a config manager's tree has a source
// every machine it manages may share. Writing this machine's client id there
// would make it every machine's, so Save hands back the lines instead.
func TestSave_RefusesAConfigFileLinkedFromAConfigManager(t *testing.T) {
	configHome(t)
	source := filepath.Join(t.TempDir(), "shared-tree", "config.toml")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("theme = \"dark\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := ConfigPath("myapp")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}

	d := Deployment{
		Path:     link,
		API:      Setting{Value: "https://myapp.example.com", Source: SourceCommandLine},
		Issuer:   Setting{Value: "https://auth.example.com", Source: SourceDiscovered},
		ClientID: Setting{Value: "myapp-cli-workstation", Source: SourceHostname},
	}
	err := d.Save()
	if err == nil || !strings.Contains(err.Error(), `client_id = "myapp-cli-workstation"`) {
		t.Errorf("err = %v, want a refusal carrying the lines to add", err)
	}
	if content, _ := os.ReadFile(source); string(content) != "theme = \"dark\"\n" {
		t.Errorf("Save wrote into the linked source:\n%s", content)
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
