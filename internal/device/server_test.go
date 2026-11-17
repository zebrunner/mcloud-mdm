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
	code, body := get(t, srv.URL+"/mdm/enroll?udid=00008020-0005308201DA002E", "0123456789abcdef")
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
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
