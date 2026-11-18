package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const udid2 = "00008120-0010359E0240201E"

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func TestJobIOS(t *testing.T) {
	hub, srv, _ := setup(t)
	enrollDevice(t, srv, udid)
	enrollDevice(t, srv, udid2)
	code, out := postJSON(t, srv.URL+"/api/jobs", map[string]any{
		"platform": "ios", "devices": []string{udid, udid2, "00008020-000000000000000A", udid},
		"actions": []map[string]any{
			{"kind": "preset", "name": "airdrop-off", "on": true},
			{"kind": "command", "name": "Settings: TimeZone", "args": map[string]any{"Settings": []any{map[string]any{"Item": "TimeZone", "TimeZone": "UTC"}}}},
			{"kind": "push"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("job: %d %v", code, out)
	}
	var jobs []Job
	eventually(t, "the job finished", func() bool {
		getJSON(t, srv.URL+"/api/jobs", &jobs)
		return len(jobs) == 1 && jobs[0].FinishedAt != ""
	})
	job := jobs[0]
	if job.ID != out["id"] || len(job.Targets) != 3 || job.Title != "3 actions" {
		t.Fatalf("job: %+v", job)
	}
	for _, target := range job.Targets {
		want := "ok"
		if target.Device == "00008020-000000000000000A" {
			want = "error"
		}
		if target.Status != want || len(target.Steps) != 3 {
			t.Errorf("%s: %s, %d steps", target.Device, target.Status, len(target.Steps))
		}
		if want == "ok" && (target.Steps[0].Title != "Turn AirDrop off: on" || target.Steps[0].UUID == "" || target.Steps[1].Status != "ok") {
			t.Errorf("%s steps: %+v %+v", target.Device, target.Steps[0], target.Steps[1])
		}
	}
	if n := len(hub.sent("InstallProfile")); n != 2 {
		t.Errorf("InstallProfile sent %d times", n)
	}
	if n := len(hub.sent("Settings")); n != 2 {
		t.Errorf("Settings sent %d times", n)
	}
	hub.mu.Lock()
	pushes := strings.Count(strings.Join(hub.requests, "\n"), "/api/v1/nanomdm/push/")
	hub.mu.Unlock()
	if pushes < 2 {
		t.Errorf("push sent %d times", pushes)
	}
	for _, bad := range []map[string]any{
		{"platform": "ios", "devices": []string{udid}, "actions": []map[string]any{{"kind": "preset", "name": "nothing", "on": true}}},
		{"platform": "ios", "devices": []string{}, "actions": []map[string]any{{"kind": "push"}}},
		{"platform": "ios", "devices": []string{udid}, "actions": []map[string]any{}},
		{"platform": "android", "devices": []string{"R3CX80DGJ1P"}, "actions": []map[string]any{{"kind": "preset", "name": "erase-off", "on": true}}},
		{"platform": "windows", "devices": []string{udid}, "actions": []map[string]any{{"kind": "push"}}},
	} {
		if code, _ := postJSON(t, srv.URL+"/api/jobs", bad); code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, code)
		}
	}
}

func TestSets(t *testing.T) {
	_, srv, st := setup(t)
	set := map[string]any{"platform": "ios", "name": " Farm ", "actions": []map[string]any{
		{"kind": "preset", "name": "wifi-allowed-only", "on": true, "params": map[string]any{"ssid": "LAB", "password": "secret", "encryption": "WPA2"}},
		{"kind": "preset", "name": "airdrop-off", "on": false},
	}}
	if code, out := postJSON(t, srv.URL+"/api/sets/save", set); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	raw, _ := json.Marshal(st.Sets())
	if strings.Contains(string(raw), "secret") || !strings.Contains(string(raw), `"ssid":"LAB"`) || !strings.Contains(string(raw), `"name":"Farm"`) {
		t.Errorf("saved: %s", raw)
	}
	set["actions"] = []map[string]any{{"kind": "push"}}
	if code, _ := postJSON(t, srv.URL+"/api/sets/save", set); code != http.StatusOK || len(st.Sets()) != 1 || len(st.Sets()[0].Actions) != 1 {
		t.Errorf("replace: %d %v", code, st.Sets())
	}
	for _, bad := range []map[string]any{
		{"platform": "ios", "name": "", "actions": []map[string]any{{"kind": "push"}}},
		{"platform": "ios", "name": "x", "actions": []map[string]any{{"kind": "preset", "name": "nothing"}}},
		{"platform": "android", "name": "x", "actions": []map[string]any{{"kind": "preset", "name": "erase-off"}}},
	} {
		if code, _ := postJSON(t, srv.URL+"/api/sets/save", bad); code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, code)
		}
	}
	var sets []map[string]any
	getJSON(t, srv.URL+"/api/sets", &sets)
	if len(sets) != 1 {
		t.Errorf("sets: %v", sets)
	}
	if code, _ := postJSON(t, srv.URL+"/api/sets/delete", map[string]any{"platform": "ios", "name": "Farm"}); code != http.StatusOK || len(st.Sets()) != 0 {
		t.Errorf("delete: %d", code)
	}
	if code, _ := postJSON(t, srv.URL+"/api/sets/delete", map[string]any{"platform": "ios", "name": "Farm"}); code != http.StatusBadRequest {
		t.Errorf("delete again: %d", code)
	}
}
