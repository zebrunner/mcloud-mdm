package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/stf"
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
	var sets struct {
		Sets     []map[string]any             `json:"sets"`
		Assigned map[string]map[string]string `json:"assigned"`
	}
	getJSON(t, srv.URL+"/api/sets", &sets)
	if len(sets.Sets) != 1 || sets.Assigned["ios"] == nil {
		t.Errorf("sets: %+v", sets)
	}
	if code, _ := postJSON(t, srv.URL+"/api/sets/delete", map[string]any{"platform": "ios", "name": "Farm"}); code != http.StatusOK || len(st.Sets()) != 0 {
		t.Errorf("delete: %d", code)
	}
	if code, _ := postJSON(t, srv.URL+"/api/sets/delete", map[string]any{"platform": "ios", "name": "Farm"}); code != http.StatusBadRequest {
		t.Errorf("delete again: %d", code)
	}
}

func waitJob(t *testing.T, url, id string) Job {
	t.Helper()
	var found Job
	eventually(t, "the job "+id+" finished", func() bool {
		var jobs []Job
		getJSON(t, url+"/api/jobs", &jobs)
		for _, j := range jobs {
			if j.ID == id && j.FinishedAt != "" {
				found = j
				return true
			}
		}
		return false
	})
	return found
}

func TestJobOptions(t *testing.T) {
	_, srv, _, s := setupServer(t)
	enrollDevice(t, srv, udid)
	enrollDevice(t, srv, udid2)
	// free only without STF
	if code, _ := postJSON(t, srv.URL+"/api/jobs", map[string]any{"platform": "ios", "devices": []string{udid}, "free_only": true,
		"actions": []map[string]any{{"kind": "push"}}}); code != http.StatusBadRequest {
		t.Errorf("free only without STF: %d", code)
	}
	// STF: udid in use until busy is cleared, udid2 disconnected
	var busy atomic.Bool
	busy.Store(true)
	stfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner := "null"
		if busy.Load() {
			owner = `{"email":"qa@example.com"}`
		}
		_, _ = w.Write([]byte(`{"devices":[{"serial":"` + udid + `","present":true,"owner":` + owner + `},{"serial":"` + udid2 + `","present":false}]}`))
	}))
	t.Cleanup(stfSrv.Close)
	s.STF = stf.New(stfSrv.URL, "tok")
	s.STF.TTL = 0
	freePoll = 50 * time.Millisecond
	t.Cleanup(func() { freePoll = 30 * time.Second })
	until := time.Now().Add(1500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	code, out := postJSON(t, srv.URL+"/api/jobs", map[string]any{"platform": "ios", "devices": []string{udid, udid2}, "free_only": true,
		"until": until, "actions": []map[string]any{{"kind": "push"}}})
	if code != http.StatusOK {
		t.Fatalf("free only: %d %v", code, out)
	}
	eventually(t, "the device waits for its user", func() bool {
		var jobs []Job
		getJSON(t, srv.URL+"/api/jobs", &jobs)
		return strings.Contains(jobs[0].Targets[0].Note, "in use by qa@example.com")
	})
	busy.Store(false)
	job := waitJob(t, srv.URL, out["id"].(string))
	if job.Targets[0].Status != "ok" || job.Targets[1].Status != "skipped" || !strings.Contains(job.Targets[1].Note, "disconnected") {
		t.Errorf("targets: %+v %+v", job.Targets[0], job.Targets[1])
	}
	// a delayed job cancelled before its start
	start := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	code, out = postJSON(t, srv.URL+"/api/jobs", map[string]any{"platform": "ios", "devices": []string{udid}, "start_at": start,
		"actions": []map[string]any{{"kind": "push"}}})
	if code != http.StatusOK {
		t.Fatalf("delayed: %d %v", code, out)
	}
	if code, _ := postJSON(t, srv.URL+"/api/jobs/cancel", map[string]any{"id": out["id"]}); code != http.StatusOK {
		t.Errorf("cancel: %d", code)
	}
	if job := waitJob(t, srv.URL, out["id"].(string)); !job.Cancelled || job.Targets[0].Status != "cancelled" || job.Targets[0].Steps[0].Status != "cancelled" {
		t.Errorf("cancelled: %+v", job)
	}
	if code, _ := postJSON(t, srv.URL+"/api/jobs/cancel", map[string]any{"id": out["id"]}); code != http.StatusBadRequest {
		t.Errorf("cancel again: %d", code)
	}
	for _, bad := range []map[string]any{{"start_at": "tomorrow"}, {"until": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}} {
		body := map[string]any{"platform": "ios", "devices": []string{udid}, "actions": []map[string]any{{"kind": "push"}}}
		for k, v := range bad {
			body[k] = v
		}
		if code, _ := postJSON(t, srv.URL+"/api/jobs", body); code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, code)
		}
	}
	var farm map[string]any
	getJSON(t, srv.URL+"/api/farm", &farm)
	if farm["enabled"] != true || farm["devices"].(map[string]any)[udid] == nil {
		t.Errorf("farm: %v", farm)
	}
}

func TestDefaultSetOnEnrollment(t *testing.T) {
	hub, srv, st := setup(t)
	if code, out := postJSON(t, srv.URL+"/api/sets/save", map[string]any{"platform": "ios", "name": "Base", "actions": []map[string]any{
		{"kind": "preset", "name": "airdrop-off", "on": true},
		{"kind": "preset", "name": "wifi-allowed-only", "on": true, "params": map[string]any{"ssid": "LAB", "password": "x"}},
	}}); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	if code, _ := postJSON(t, srv.URL+"/api/sets/default", map[string]any{"platform": "ios", "name": "Base"}); code != http.StatusOK {
		t.Fatalf("default: %d", code)
	}
	enrollDevice(t, srv, udid)
	var jobs []Job
	eventually(t, "the set of the enrollment applied", func() bool {
		getJSON(t, srv.URL+"/api/jobs", &jobs)
		return len(jobs) == 1 && jobs[0].FinishedAt != ""
	})
	steps := jobs[0].Targets[0].Steps
	if jobs[0].Title != `Set "Base" (enrollment)` || steps[0].Status != "ok" || steps[1].Status != "error" || !strings.Contains(steps[1].Output, "password is not stored") {
		t.Errorf("job: %+v %+v %+v", jobs[0], steps[0], steps[1])
	}
	if len(hub.sent("InstallProfile")) != 1 {
		t.Errorf("InstallProfile: %d (the Wi-Fi without its password must not go)", len(hub.sent("InstallProfile")))
	}
	if st.Assigned()["ios"][udid] != "Base" {
		t.Errorf("the default set is not assigned: %v", st.Assigned())
	}
	// an explicit assignment, then its removal
	if code, _ := postJSON(t, srv.URL+"/api/sets/assign", map[string]any{"platform": "ios", "name": "", "devices": []string{udid}}); code != http.StatusOK || st.Assigned()["ios"][udid] != "" {
		t.Errorf("unassign: %d", code)
	}
	if code, _ := postJSON(t, srv.URL+"/api/sets/assign", map[string]any{"platform": "ios", "name": "Nothing", "devices": []string{udid}}); code != http.StatusBadRequest {
		t.Errorf("assign an unknown set: %d", code)
	}
}
