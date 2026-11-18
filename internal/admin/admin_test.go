package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/zebrunner/mcloud-mdm/internal/config"
	"github.com/zebrunner/mcloud-mdm/internal/nanohub"
	"github.com/zebrunner/mcloud-mdm/internal/state"
)

const udid = "00008020-0005308201DA002E"

// fakeHub records the requests to NanoHUB and acknowledges every enqueued command through the webhook of admin
type fakeHub struct {
	mu       sync.Mutex
	requests []string
	commands []map[string]any
	admin    string
}

func (f *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/api/v1/nanomdm/enqueue/") {
		var cmd map[string]any
		_, _ = plist.Unmarshal(body, &cmd)
		f.mu.Lock()
		f.commands = append(f.commands, cmd)
		f.mu.Unlock()
		uuid := cmd["CommandUUID"].(string)
		// the device of the path: several devices in a job
		device := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		report := map[string]any{"CommandUUID": uuid, "Status": "Acknowledged", "UDID": device}
		if cmd["Command"].(map[string]any)["RequestType"] == "ProfileList" {
			report["ProfileList"] = []any{map[string]any{"PayloadIdentifier": "com.zebrunner.mcloud.mdm.preset.airdrop-off"}}
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			hook(f.admin, "mdm.Connect", map[string]any{"udid": device, "status": "Acknowledged", "command_uuid": uuid}, report)
		}()
	}
	_, _ = io.WriteString(w, `{}`)
}

func (f *fakeHub) sent(requestType string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, c := range f.commands {
		cmd := c["Command"].(map[string]any)
		if cmd["RequestType"] == requestType {
			out = append(out, cmd)
		}
	}
	return out
}

func hook(base, topic string, body map[string]any, report map[string]any) {
	raw, _ := plist.Marshal(report, plist.XMLFormat)
	body["raw_payload"] = base64.StdEncoding.EncodeToString(raw)
	key := "checkin_event"
	if topic == "mdm.Connect" {
		key = "acknowledge_event"
	}
	data, _ := json.Marshal(map[string]any{"topic": topic, key: body})
	resp, err := http.Post(base+"/webhook", "application/json", bytes.NewReader(data))
	if err == nil {
		resp.Body.Close()
	}
}

func setup(t *testing.T) (*fakeHub, *httptest.Server, *state.Store) {
	t.Helper()
	hub, srv, st, _ := setupServer(t)
	return hub, srv, st
}

func setupServer(t *testing.T) (*fakeHub, *httptest.Server, *state.Store, *Server) {
	t.Helper()
	hub := &fakeHub{}
	hubSrv := httptest.NewServer(hub)
	t.Cleanup(hubSrv.Close)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Config:  &config.Config{PublicURL: "https://m.example.com", SCEPURL: "https://m.example.com/scep", OrgName: "Org"},
		NanoHUB: nanohub.New(hubSrv.URL, "k"), State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		AnswerTimeout: 5 * time.Second, RefreshDelay: 10 * time.Millisecond,
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	hub.admin = srv.URL
	return hub, srv, st, s
}

func postJSON(t *testing.T, url string, body any, headers ...string) (int, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func enroll(t *testing.T, srv *httptest.Server) {
	t.Helper()
	enrollDevice(t, srv, udid)
}

func enrollDevice(t *testing.T, srv *httptest.Server, udid string) {
	t.Helper()
	hook(srv.URL, "mdm.Authenticate", map[string]any{"udid": udid}, map[string]any{"UDID": udid, "SerialNumber": "SER", "ProductName": "iPhone11,8", "OSVersion": "18.7.11"})
	hook(srv.URL, "mdm.TokenUpdate", map[string]any{"udid": udid}, map[string]any{"UDID": udid, "UnlockToken": []byte("unlock")})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("not reached: %s", what)
}

func TestEnrollmentAndCommands(t *testing.T) {
	hub, srv, st := setup(t)
	if code, _ := postJSON(t, srv.URL+"/api/command", map[string]any{"udid": udid, "type": "ProfileList"}); code != http.StatusBadRequest {
		t.Errorf("a command to a device not enrolled: %d", code)
	}
	enroll(t, srv)
	// a new enrollment: DDM notify and ProfileList
	eventually(t, "DDM notify and ProfileList after the enrollment", func() bool {
		hub.mu.Lock()
		notified := strings.Contains(strings.Join(hub.requests, "\n"), "POST /api/v1/ddm/notify?id="+udid)
		hub.mu.Unlock()
		return notified && len(hub.sent("ProfileList")) == 1
	})
	code, out := postJSON(t, srv.URL+"/api/command", map[string]any{"udid": udid, "type": "ClearPasscode", "args": map[string]any{}})
	if code != http.StatusOK {
		t.Fatalf("ClearPasscode: %d %v", code, out)
	}
	clear := hub.sent("ClearPasscode")
	if len(clear) != 1 || string(clear[0]["UnlockToken"].([]byte)) != "unlock" {
		t.Errorf("the unlock token is not filled in: %v", clear)
	}
	eventually(t, "the report of ClearPasscode", func() bool { return st.Status(out["uuid"].(string)) == "Acknowledged" })
	view, _ := json.Marshal(st.View())
	if strings.Contains(string(view), base64.StdEncoding.EncodeToString([]byte("unlock"))) {
		t.Error("the unlock token is shown")
	}
	// "Settings: TimeZone" of the catalog is the request type Settings
	if code, _ := postJSON(t, srv.URL+"/api/command", map[string]any{"udid": udid, "type": "Settings: TimeZone",
		"args": map[string]any{"Settings": []any{map[string]any{"Item": "TimeZone", "TimeZone": "UTC"}}}}); code != http.StatusOK ||
		len(hub.sent("Settings")) != 1 {
		t.Errorf("Settings preset: %d", code)
	}
}

func TestPresetInstall(t *testing.T) {
	hub, srv, _ := setup(t)
	enroll(t, srv)
	code, out := postJSON(t, srv.URL+"/api/preset/install", map[string]any{"udid": udid, "name": "bluetooth-off"})
	if code != http.StatusOK || !strings.Contains(out["output"].(string), "Settings: Acknowledged") ||
		!strings.Contains(out["output"].(string), "InstallProfile com.zebrunner.mcloud.mdm.preset.bluetooth-off: Acknowledged") {
		t.Fatalf("install: %d %v", code, out)
	}
	install := hub.sent("InstallProfile")
	var profile map[string]any
	if _, err := plist.Unmarshal(install[0]["Payload"].([]byte), &profile); err != nil || profile["PayloadIdentifier"] != "com.zebrunner.mcloud.mdm.preset.bluetooth-off" {
		t.Errorf("payload: %v %v", err, profile)
	}
	resp, _ := http.Get(srv.URL + "/api/state")
	var st map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	marks := st["profiles"].(map[string]any)[udid].(map[string]any)
	if marks["stale"] != false || !strings.Contains(strings.Join(toStrings(marks["ids"]), ","), "airdrop-off") {
		t.Errorf("installed marks: %v", marks)
	}
	if code, _ := postJSON(t, srv.URL+"/api/preset/install", map[string]any{"udid": udid, "name": "wifi-allowed-only", "params": map[string]any{"ssid": ""}}); code != http.StatusBadRequest {
		t.Errorf("wifi without ssid: %d", code)
	}
}

func toStrings(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, s := range list {
		out = append(out, s.(string))
	}
	return out
}

func TestCheckOutClearsAndStale(t *testing.T) {
	_, srv, st := setup(t)
	enroll(t, srv)
	eventually(t, "ProfileList after the enrollment", func() bool {
		v := st.View()
		return len(v.Commands) > 0 && v.Commands[0].Status == "Acknowledged"
	})
	time.Sleep(1100 * time.Millisecond)
	hook(srv.URL, "mdm.CheckOut", map[string]any{"udid": udid}, map[string]any{"UDID": udid})
	if st.Enrolled(udid) {
		t.Error("enrolled after CheckOut")
	}
	v := st.View()
	if marks := installed(v)[udid].(map[string]any); marks["stale"] != true {
		t.Errorf("the ProfileList before CheckOut is not stale: %v", marks)
	}
}

func TestGuards(t *testing.T) {
	_, srv, _ := setup(t)
	enroll(t, srv)
	if code, _ := postJSON(t, srv.URL+"/api/push", map[string]any{"udid": udid}, "Origin", "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", code)
	}
	resp, _ := http.Post(srv.URL+"/api/push", "text/plain", strings.NewReader(`{"udid":"x"}`))
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a form post: %d", resp.StatusCode)
	}
	resp.Body.Close()
	for _, path := range []string{"/etc/passwd", "/api/v1/../../x", "http://evil/api/v1/"} {
		if code, _ := postJSON(t, srv.URL+"/api/raw", map[string]any{"method": "GET", "path": path}); code != http.StatusBadRequest {
			t.Errorf("raw %s: %d", path, code)
		}
	}
	if code, out := postJSON(t, srv.URL+"/api/raw", map[string]any{"method": "GET", "path": "/version"}); code != http.StatusOK || out["status"] != float64(200) {
		t.Errorf("raw /version: %d %v", code, out)
	}
	if code, _ := postJSON(t, srv.URL+"/api/pushcert", map[string]any{"pem": "nothing"}); code != http.StatusBadRequest {
		t.Errorf("pushcert without PEM: %d", code)
	}
}

func TestStatic(t *testing.T) {
	_, srv, _ := setup(t)
	for path, want := range map[string]string{"/": "<title>MCloud MDM</title>", "/api/catalog": `"DeviceInformation"`, "/api/presets": `"wifi-allowed-only"`} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	var catalog []map[string]any
	data, _ := web.ReadFile("web/catalog.json")
	if err := json.Unmarshal(data, &catalog); err != nil || len(catalog) < 50 {
		t.Fatalf("catalog: %v %d", err, len(catalog))
	}
	for _, c := range catalog {
		if c["hint"] == "" || c["type"] == "" || c["group"] == "" {
			t.Errorf("catalog entry without a hint: %v", c)
		}
	}
}
