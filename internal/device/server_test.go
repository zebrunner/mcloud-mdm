package device

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/zebrunner/mcloud-mdm/internal/android"
	"github.com/zebrunner/mcloud-mdm/internal/config"
	"github.com/zebrunner/mcloud-mdm/internal/scep"
	"github.com/zebrunner/mcloud-mdm/internal/state"
)

func server(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	ca, _, err := scep.LoadOrCreateCA(dir, "Org")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &config.Config{PublicURL: "https://m.example.com", SCEPURL: "https://m.example.com/scep",
		EnrollToken: "0123456789abcdef", ProfileID: "com.example.mdm", OrgName: "Org"}
	s, err := New(c, &scep.Server{CA: ca, Challenges: scep.NewChallenges(time.Minute), Days: 1, Log: log}, st, log)
	if err != nil {
		t.Fatal(err)
	}
	return s, httptest.NewServer(s.Handler())
}

func get(t *testing.T, url, token string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestEnroll(t *testing.T) {
	s, srv := server(t)
	defer srv.Close()
	if code, _ := get(t, srv.URL+"/mdm/enroll", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := get(t, srv.URL+"/mdm/enroll", "wrong-token-000000"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	if code, body := get(t, srv.URL+"/mdm/enroll", "0123456789abcdef"); code != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), "push certificate") {
		t.Errorf("no push certificate: %d %s", code, body)
	}
	_ = s.State.SetPushCert("com.apple.mgmt.External.t", "2027")
	if code, _ := get(t, srv.URL+"/mdm/enroll?udid=../../x", "0123456789abcdef"); code != http.StatusBadRequest {
		t.Errorf("invalid udid: %d", code)
	}
	code, body := get(t, srv.URL+"/mdm/enroll?udid=00008020-0005308201DA002E&name=iPhone_XR", "0123456789abcdef")
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}
	if name := s.State.Name("00008020-0005308201DA002E"); name != "iPhone_XR" {
		t.Errorf("the name of the device: %q", name)
	}
	if _, known := s.State.Device("00008020-0005308201DA002E"); known {
		t.Error("a profile request is not an enrollment")
	}
	var m map[string]any
	if _, err := plist.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	var challenge, subject string
	for _, p := range m["PayloadContent"].([]any) {
		pm := p.(map[string]any)
		if pm["PayloadType"] == "com.apple.security.scep" {
			c := pm["PayloadContent"].(map[string]any)
			challenge = c["Challenge"].(string)
			subject = c["Subject"].([]any)[0].([]any)[0].([]any)[1].(string)
		}
	}
	if !strings.HasPrefix(subject, "mcloud-mdm-00008020-0005308201DA002E-") {
		t.Errorf("subject %q", subject)
	}
	if !s.SCEP.Challenges.Consume(challenge) || s.SCEP.Challenges.Consume(challenge) {
		t.Error("the challenge of the profile is not one-time")
	}
}

func TestHealth(t *testing.T) {
	_, srv := server(t)
	defer srv.Close()
	if code, body := get(t, srv.URL+"/healthz", ""); code != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("health: %d %s", code, body)
	}
	if code, _ := get(t, srv.URL+"/scep?operation=GetCACaps", ""); code != http.StatusOK {
		t.Errorf("scep: %d", code)
	}
	if code, _ := get(t, srv.URL+"/api/state", ""); code != http.StatusNotFound {
		t.Errorf("the admin API on the device listener: %d", code)
	}
}

func TestAndroidEndpoints(t *testing.T) {
	s, srv := server(t)
	defer srv.Close()
	s.Config.AgentAPK = t.TempDir() + "/agent.apk"
	if code, _ := get(t, srv.URL+"/android/enroll?serial=SER001", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := get(t, srv.URL+"/android/enroll?serial=SER001", "0123456789abcdef"); code != http.StatusNotFound {
		t.Errorf("no Headwind MDM: %d", code)
	}
	if code, _ := get(t, srv.URL+"/android/status?serial=SER001", "0123456789abcdef"); code != http.StatusNotFound {
		t.Errorf("status without Headwind MDM: %d", code)
	}
	if code, _ := get(t, srv.URL+"/android/release", ""); code != http.StatusUnauthorized {
		t.Errorf("release without the token: %d", code)
	}
	s.Android = &android.Manager{Secret: "0123456789abcdef0123"}
	code, body := get(t, srv.URL+"/android/release", "0123456789abcdef")
	if code != http.StatusOK || !strings.Contains(string(body), "--method release --extra token:s:0123456789abcdef0123") {
		t.Errorf("release: %d %q", code, body)
	}
	if code, _ := get(t, srv.URL+"/android/agent.apk", ""); code != http.StatusNotFound {
		t.Errorf("no APK: %d", code)
	}
	if err := os.WriteFile(s.Config.AgentAPK, []byte("PK apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, srv.URL+"/android/agent.apk", ""); code != http.StatusOK || string(body) != "PK apk" {
		t.Errorf("APK: %d %q", code, body)
	}
}

type fakeCommander struct {
	sent []string
	args []map[string]any
}

func (f *fakeCommander) Send(udid, requestType string, args map[string]any) (string, error) {
	f.sent = append(f.sent, udid+" "+requestType)
	f.args = append(f.args, args)
	return "CMD-1", nil
}

func (f *fakeCommander) Enrolled(platform, device string) {}

func post(t *testing.T, url, token string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestIOSStatusAndRelease(t *testing.T) {
	s, srv := server(t)
	defer srv.Close()
	cmds := &fakeCommander{}
	s.Commands = cmds
	const token, udid = "0123456789abcdef", "00008020-0005308201DA002E"
	if code, _ := get(t, srv.URL+"/mdm/status?udid="+udid, ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := get(t, srv.URL+"/mdm/status?udid=x;y", token); code != http.StatusBadRequest {
		t.Errorf("bad udid: %d", code)
	}
	code, body := get(t, srv.URL+"/mdm/status?udid="+udid+"&format=shell", token)
	if code != http.StatusOK || string(body) != "udid="+udid+"\nknown=no\nenrolled=no\n" {
		t.Errorf("unknown device: %d %q", code, body)
	}
	if code, _ := post(t, srv.URL+"/mdm/release?udid="+udid, token); code != http.StatusConflict || len(cmds.sent) != 0 {
		t.Errorf("release of a device that is not enrolled: %d %v", code, cmds.sent)
	}
	if err := s.State.Authenticate(udid, "F71X", "iPhone11,8", "18.7.11"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.State.TokenUpdate(udid, nil); err != nil {
		t.Fatal(err)
	}
	code, body = get(t, srv.URL+"/mdm/status?udid="+udid, token)
	if code != http.StatusOK || !strings.Contains(string(body), `"enrolled":"yes"`) || !strings.Contains(string(body), `"product":"iPhone11,8"`) {
		t.Errorf("enrolled device: %d %s", code, body)
	}
	code, body = post(t, srv.URL+"/mdm/release?udid="+udid+"&format=shell", token)
	if code != http.StatusAccepted || !strings.Contains(string(body), "command=CMD-1") ||
		len(cmds.sent) != 1 || cmds.sent[0] != udid+" RemoveProfile" || cmds.args[0]["Identifier"] != "com.example.mdm" {
		t.Errorf("release: %d %q %v %v", code, body, cmds.sent, cmds.args)
	}
	if code, _ := get(t, srv.URL+"/mdm/release?udid="+udid, token); code != http.StatusMethodNotAllowed {
		t.Errorf("release by GET: %d", code)
	}
}

type fakeNodes struct {
	nodes map[string]string
	err   error
	calls []string
}

func (f *fakeNodes) DeviceNode(serial string) (string, bool, error) {
	f.calls = append(f.calls, serial)
	if f.err != nil {
		return "", false, f.err
	}
	node, ok := f.nodes[serial]
	return node, ok, nil
}

func call(t *testing.T, method, url, node string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef")
	if node != "" {
		req.Header.Set(NodeHeader, node)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestNodeBinding(t *testing.T) {
	s, srv := server(t)
	defer srv.Close()
	const ownUDID, otherUDID, secret = "00008020-0005308201DA002E", "00008020-0005308201DA00FF", "0123456789abcdef0123"
	cmds := &fakeCommander{}
	nodes := &fakeNodes{nodes: map[string]string{ownUDID: "node-a", "SER-A": "node-a", otherUDID: "node-b",
		"SER-B": "node-b", "SER-FREE": ""}}
	s.Commands, s.Nodes = cmds, nodes
	s.Android = &android.Manager{Secret: secret}
	s.Config.EnforceNodeBinding = true
	_ = s.State.SetPushCert("com.apple.mgmt.External.t", "2027")
	if err := s.State.Authenticate(otherUDID, "F71X", "iPhone11,8", "18.7.11"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.State.TokenUpdate(otherUDID, nil); err != nil {
		t.Fatal(err)
	}
	foreign := [][2]string{
		{http.MethodGet, "/mdm/enroll?udid=" + otherUDID}, {http.MethodGet, "/mdm/status?udid=" + otherUDID},
		{http.MethodPost, "/mdm/release?udid=" + otherUDID}, {http.MethodGet, "/android/enroll?serial=SER-B"},
		{http.MethodGet, "/android/status?serial=SER-B"}, {http.MethodGet, "/android/release?serial=SER-B"},
		{http.MethodGet, "/android/release?serial=SER-FREE"}, {http.MethodGet, "/android/release?serial=SER-UNKNOWN"},
	}
	// another node, no node (an older proxy), not a label
	for _, node := range []string{"node-a", "", "Node A"} {
		for _, c := range foreign {
			code, body := call(t, c[0], srv.URL+c[1], node)
			if code != http.StatusForbidden || string(body) != "forbidden\n" {
				t.Errorf("%q %s: %d %q", node, c[1], code, body)
			}
		}
	}
	if len(cmds.sent) != 0 || s.SCEP.Challenges.Pending() != 0 || s.State.Name(otherUDID) != "" {
		t.Errorf("a refused call acted: %v %d", cmds.sent, s.SCEP.Challenges.Pending())
	}
	for _, c := range [][2]string{{http.MethodGet, "/android/release"}, {http.MethodGet, "/mdm/enroll"},
		{http.MethodGet, "/android/release?serial=a;b"}} {
		if code, _ := call(t, c[0], srv.URL+c[1], "node-a"); code != http.StatusBadRequest {
			t.Errorf("%s: %d", c[1], code)
		}
	}
	// the devices of the node
	if code, body := call(t, http.MethodGet, srv.URL+"/android/release?serial=SER-A", "node-a"); code != http.StatusOK ||
		!strings.Contains(string(body), "token:s:"+secret) {
		t.Errorf("release of its own device: %d %q", code, body)
	}
	if code, body := call(t, http.MethodGet, srv.URL+"/mdm/status?udid="+ownUDID+"&format=shell", "node-a"); code != http.StatusOK ||
		!strings.Contains(string(body), "known=no") {
		t.Errorf("status of its own device: %d %q", code, body)
	}
	if code, _ := call(t, http.MethodPost, srv.URL+"/mdm/release?udid="+otherUDID, "node-b"); code != http.StatusAccepted ||
		len(cmds.sent) != 1 {
		t.Errorf("release of its own device: %d %v", code, cmds.sent)
	}
	code, body := call(t, http.MethodGet, srv.URL+"/mdm/enroll?udid="+ownUDID+"&name=iPhone", "node-a")
	if code != http.StatusOK {
		t.Fatalf("enroll of its own device: %d %s", code, body)
	}
	var m map[string]any
	if _, err := plist.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	var challenge string
	for _, p := range m["PayloadContent"].([]any) {
		if pm := p.(map[string]any); pm["PayloadType"] == "com.apple.security.scep" {
			challenge = pm["PayloadContent"].(map[string]any)["Challenge"].(string)
		}
	}
	if udid, ok := s.SCEP.Challenges.Take(challenge); !ok || udid != ownUDID {
		t.Errorf("the challenge is not bound to the device: %q %v", udid, ok)
	}
	// STF does not answer: refused too
	nodes.err = io.ErrUnexpectedEOF
	if code, body := call(t, http.MethodGet, srv.URL+"/android/release?serial=SER-A", "node-a"); code != http.StatusServiceUnavailable ||
		strings.Contains(string(body), secret) {
		t.Errorf("no STF: %d %q", code, body)
	}
}

func TestNodeBindingOff(t *testing.T) {
	s, srv := server(t)
	defer srv.Close()
	nodes := &fakeNodes{nodes: map[string]string{"SER-B": "node-b"}}
	s.Nodes = nodes
	s.Android = &android.Manager{Secret: "0123456789abcdef0123"}
	_ = s.State.SetPushCert("com.apple.mgmt.External.t", "2027")
	for _, path := range []string{"/android/release", "/android/release?serial=SER-B", "/mdm/enroll",
		"/mdm/status?udid=00008020-0005308201DA00FF"} {
		if code, body := call(t, http.MethodGet, srv.URL+path, "node-a"); code != http.StatusOK {
			t.Errorf("%s: %d %q", path, code, body)
		}
	}
	if len(nodes.calls) != 0 {
		t.Errorf("STF asked without the setting: %v", nodes.calls)
	}
	challenge, _ := s.SCEP.Challenges.New()
	if udid, ok := s.SCEP.Challenges.Take(challenge); !ok || udid != "" {
		t.Errorf("a challenge bound without the setting: %q", udid)
	}
}
