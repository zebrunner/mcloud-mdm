package android

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/zebrunner/mcloud-mdm/internal/headwind"
)

// fake is Headwind MDM in memory: the endpoints mcloud-mdm uses
type fake struct {
	mu      sync.Mutex
	configs map[int]map[string]any
	apps    map[int][]map[string]any
	devices map[string]*headwind.Device
	pushes  []map[string]any
	logins  int
	nextID  int
}

func newFake() *fake {
	f := &fake{configs: map[int]map[string]any{}, apps: map[int][]map[string]any{}, devices: map[string]*headwind.Device{}, nextID: 10}
	f.configs[1] = map[string]any{"id": 1.0, "name": "Common - Minimal", "appPermissions": "GRANTALL", "password": "12345678"}
	f.apps[1] = []map[string]any{
		{"pkg": AgentPackage, "selected": true, "action": 1.0, "url": "https://h-mdm.com/files/hmdm-6.40-os.apk"},
		{"pkg": "com.hmdm.pager", "selected": true, "action": 1.0, "url": "https://h-mdm.com/files/pager-1.02.apk"},
		{"pkg": "com.android.chrome", "selected": false, "action": 1.0},
	}
	return f
}

func (f *fake) ok(w http.ResponseWriter, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "OK", "data": data})
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/rest/public/jwt/login" {
		var c map[string]string
		_ = json.NewDecoder(r.Body).Decode(&c)
		if c["login"] != "admin" || c["password"] != headwind.PasswordHash("secret") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.logins++
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "t" + strconv.Itoa(f.logins)})
		return
	}
	// the first token expires: the client logs in again
	if r.Header.Get("Authorization") != "Bearer t"+strconv.Itoa(f.logins) || f.logins < 2 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/rest/private")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case path == "/devices/search":
		items := []*headwind.Device{}
		for _, d := range f.devices {
			items = append(items, d)
		}
		f.ok(w, map[string]any{"devices": map[string]any{"items": items}})
	case path == "/devices" && r.Method == http.MethodPut:
		raw, _ := json.Marshal(body)
		var d headwind.Device
		_ = json.Unmarshal(raw, &d)
		if d.ID == 0 {
			f.nextID++
			d.ID = f.nextID
		}
		f.devices[d.Number] = &d
		f.ok(w, nil)
	case strings.HasPrefix(path, "/devices/") && r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/devices/"))
		for n, d := range f.devices {
			if d.ID == id {
				delete(f.devices, n)
			}
		}
		f.ok(w, nil)
	case path == "/configurations/search":
		list := []map[string]any{}
		for _, c := range f.configs {
			list = append(list, c)
		}
		f.ok(w, list)
	case path == "/configurations/copy":
		f.nextID++
		id := f.nextID
		from := int(body["id"].(float64))
		c := map[string]any{}
		for k, v := range f.configs[from] {
			c[k] = v
		}
		c["id"], c["name"] = float64(id), body["name"]
		f.configs[id] = c
		f.apps[id] = append([]map[string]any{}, f.apps[from]...)
		f.ok(w, nil)
	case strings.HasPrefix(path, "/configurations/applications/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/configurations/applications/"))
		f.ok(w, f.apps[id])
	case path == "/configurations" && r.Method == http.MethodPut:
		id := int(body["id"].(float64))
		apps, _ := body["applications"].([]any)
		f.apps[id] = nil
		for _, a := range apps {
			am := a.(map[string]any)
			am["selected"] = true
			f.apps[id] = append(f.apps[id], am)
		}
		delete(body, "applications")
		f.configs[id] = body
		f.ok(w, nil)
	case strings.HasPrefix(path, "/configurations/") && r.Method == http.MethodGet:
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/configurations/"))
		f.ok(w, f.configs[id])
	case strings.HasPrefix(path, "/configurations/") && r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/configurations/"))
		delete(f.configs, id)
		f.ok(w, nil)
	case path == "/push":
		f.pushes = append(f.pushes, body)
		f.ok(w, nil)
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (*fake, *Manager) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &Manager{HW: headwind.New(srv.URL, "admin", "secret"), PublicURL: "https://hmdm.example.com",
		Secret: "0123456789abcdef"}
}

func TestEnrollCreatesFarmConfiguration(t *testing.T) {
	f, m := setup(t)
	s, err := m.Enroll("96JY1BL9Z", "Pixel_3_XL", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.Configure, "--arg https://hmdm.example.com --extra deviceId:s:96JY1BL9Z --extra secret:s:0123456789abcdef --extra token:s:0123456789abcdef") {
		t.Errorf("setup command: %s", s.Configure)
	}
	if s.Release != "content call --uri content://com.hmdm.launcher.mcloud --method release --extra token:s:0123456789abcdef" {
		t.Errorf("release command: %s", s.Release)
	}
	for _, c := range s.ADB {
		if strings.Contains(c, "install -t") {
			t.Errorf("the agent is no test-only app: %s", c)
		}
	}
	d := f.devices["96JY1BL9Z"]
	cfg := f.configs[d.ConfigurationID]
	if cfg["name"] != "mcloud-96JY1BL9Z" || cfg["runDefaultLauncher"] != true || cfg["appPermissions"] != "ASKALL" ||
		cfg["permissive"] != true || cfg["password"] == "12345678" {
		t.Errorf("configuration: %v", cfg)
	}
	if apps := f.apps[d.ConfigurationID]; len(apps) != 1 || apps[0]["pkg"] != AgentPackage {
		t.Errorf("only the agent may stay in the configuration: %v", apps)
	}
	// a second enrollment reuses the configuration
	if _, err := m.Enroll("96JY1BL9Z", "", ""); err != nil || len(f.configs) != 2 {
		t.Errorf("enroll again: %v, %d configurations", err, len(f.configs))
	}
	if f.devices["96JY1BL9Z"].Description != "Pixel_3_XL" {
		t.Errorf("the name is kept: %q", f.devices["96JY1BL9Z"].Description)
	}
}

func TestEnrollRejectsSerials(t *testing.T) {
	_, m := setup(t)
	for _, serial := range []string{"", "192.168.1.5:5555", "a b", "x;rm"} {
		if _, err := m.Enroll(serial, "", ""); err == nil {
			t.Errorf("%q accepted", serial)
		}
	}
}

func TestPresets(t *testing.T) {
	f, m := setup(t)
	if _, err := m.Enroll("SER001", "", ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bluetooth-off", "erase-off", "swupdate-postpone"} {
		if err := m.SetPreset("SER001", name, true); err != nil {
			t.Fatal(err)
		}
	}
	cfg := f.configs[f.devices["SER001"].ConfigurationID]
	if cfg["restrictions"] != "no_bluetooth,no_factory_reset" || cfg["bluetooth"] != false || cfg["systemUpdateType"] != 3.0 {
		t.Errorf("on: %v", cfg)
	}
	devices, err := m.Devices()
	if err != nil || len(devices) != 1 || !devices[0].Presets["bluetooth-off"] || devices[0].Presets["wifi-locked"] || !devices[0].Pending {
		t.Errorf("devices: %+v %v", devices, err)
	}
	if err := m.SetPreset("SER001", "bluetooth-off", false); err != nil {
		t.Fatal(err)
	}
	cfg = f.configs[f.devices["SER001"].ConfigurationID]
	if cfg["restrictions"] != "no_factory_reset" || cfg["bluetooth"] != nil {
		t.Errorf("off: %v", cfg)
	}
	if err := m.SetPreset("SER001", "no-such", true); err == nil {
		t.Error("an unknown preset is accepted")
	}
	if err := m.SetPreset("SER002", "erase-off", true); err == nil {
		t.Error("an unknown device is accepted")
	}
}

func TestCommandsAndDelete(t *testing.T) {
	f, m := setup(t)
	if _, err := m.Enroll("SER001", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Send("SER001", "run-app", "com.android.settings"); err != nil {
		t.Fatal(err)
	}
	if err := m.Send("SER001", "release", ""); err != nil {
		t.Fatal(err)
	}
	if len(f.pushes) != 2 || f.pushes[0]["messageType"] != "runApp" || f.pushes[0]["payload"] != `{"pkg":"com.android.settings"}` ||
		f.pushes[1]["messageType"] != "mcloudRelease" || f.pushes[1]["payload"] != nil {
		t.Errorf("pushes: %v", f.pushes)
	}
	for _, pkg := range []string{"", "settings", "com.x;reboot", AgentPackage} {
		if err := m.Send("SER001", "clear-app-data", pkg); err == nil {
			t.Errorf("package %q accepted", pkg)
		}
	}
	if err := m.Delete("SER001"); err != nil {
		t.Fatal(err)
	}
	if len(f.devices) != 0 || len(f.configs) != 1 {
		t.Errorf("left: %v %v", f.devices, f.configs)
	}
}

func TestLoginRefused(t *testing.T) {
	f := newFake()
	srv := httptest.NewServer(f)
	defer srv.Close()
	if err := headwind.New(srv.URL, "admin", "wrong").Ping(); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("wrong password: %v", err)
	}
}
