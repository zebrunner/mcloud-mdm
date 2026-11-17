package nanohub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"howett.net/plist"
)

func TestNewCommand(t *testing.T) {
	id, data, err := NewCommand("Settings", map[string]any{
		"Settings": []any{map[string]any{"Item": "Wallpaper", "Where": float64(2), "Image": map[string]any{"$data": "AQID"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["CommandUUID"] != id || len(id) != 36 {
		t.Errorf("uuid %v %s", m["CommandUUID"], id)
	}
	cmd := m["Command"].(map[string]any)
	item := cmd["Settings"].([]any)[0].(map[string]any)
	if cmd["RequestType"] != "Settings" || item["Where"] != uint64(2) || string(item["Image"].([]byte)) != "\x01\x02\x03" {
		t.Errorf("command: %#v", cmd)
	}
	if _, _, err := NewCommand("X", map[string]any{"P": map[string]any{"$data": "!!"}}); err == nil {
		t.Error("invalid base64 accepted")
	}
}

func TestClient(t *testing.T) {
	var gotPath, gotUser, gotKey, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.RequestURI()
		gotUser, gotKey, _ = r.BasicAuth()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Path == "/api/v1/nanomdm/pushcert" {
			_, _ = io.WriteString(w, `{"topic":"com.apple.mgmt.External.t","not_after":"2027-01-01T00:00:00Z"}`)
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/", "k")
	if _, _, err := c.Enqueue("UD ID", []byte("cmd")); err != nil || gotPath != "PUT /api/v1/nanomdm/enqueue/UD%20ID" ||
		gotUser != "nanohub" || gotKey != "k" || gotBody != "cmd" {
		t.Errorf("enqueue: %v %s %s %s", err, gotPath, gotUser, gotBody)
	}
	if _, _, err := c.NotifyDDM("u&1"); err != nil || gotPath != "POST /api/v1/ddm/notify?id=u%261" {
		t.Errorf("notify: %v %s", err, gotPath)
	}
	topic, until, err := c.PushCert([]byte("pem"))
	if err != nil || topic != "com.apple.mgmt.External.t" || until == "" {
		t.Errorf("pushcert: %v %s %s", err, topic, until)
	}
}
