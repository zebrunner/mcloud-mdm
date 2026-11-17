package device

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"howett.net/plist"

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
