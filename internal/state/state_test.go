package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func store(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, &now
}

func TestEnrollmentLifecycle(t *testing.T) {
	s, now := store(t)
	if err := s.Authenticate("D1", "SER", "iPhone11,8", "18.7.11"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	if fresh, _ := s.TokenUpdate("D1", []byte("unlock")); !fresh || !s.Enrolled("D1") {
		t.Fatal("the first TokenUpdate is not a new enrollment")
	}
	*now = now.Add(time.Hour)
	if fresh, _ := s.TokenUpdate("D1", nil); fresh {
		t.Error("a later TokenUpdate is a new enrollment")
	}
	if string(s.UnlockToken("D1")) != "unlock" {
		t.Error("the unlock token is lost by a TokenUpdate without one")
	}
	_ = s.Sent(&Command{UUID: "C1", UDID: "D1", Type: "ProfileList"})
	_ = s.CheckOut("D1")
	if s.Enrolled("D1") || s.Status("C1") != "Cleared" {
		t.Errorf("after CheckOut: enrolled=%v status=%s", s.Enrolled("D1"), s.Status("C1"))
	}
	*now = now.Add(time.Minute)
	_ = s.Authenticate("D1", "SER", "iPhone11,8", "18.7.11")
	if fresh, _ := s.TokenUpdate("D1", nil); !fresh || !s.Enrolled("D1") {
		t.Error("the enrollment after CheckOut is not new")
	}
}

func TestAnswered(t *testing.T) {
	s, _ := store(t)
	_ = s.Sent(&Command{UUID: "C1", UDID: "D1", Type: "DeviceInformation"})
	if s.Status("C1") != "Queued" {
		t.Fatal("not queued")
	}
	_ = s.Answered("D1", "C1", "Acknowledged", "DeviceInformation", map[string]any{"x": 1})
	_ = s.Answered("D1", "C2", "Acknowledged", "DeclarativeManagement", nil)
	_ = s.Answered("D1", "", "Idle", "", nil)
	v := s.View()
	if len(v.Commands) != 2 || v.Commands[0].Type != "DeclarativeManagement (outside the UI)" || v.Commands[1].Status != "Acknowledged" {
		t.Errorf("commands: %+v", v.Commands)
	}
	if len(v.Events) != 3 || v.Events[0].Event != "Connect Idle" || !strings.HasPrefix(v.Events[1].Event, "Connect Acknowledged C2") {
		t.Errorf("events: %+v", v.Events)
	}
}

func TestPersistedWithoutUnlockInView(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Authenticate("D1", "", "", "")
	_, _ = s.TokenUpdate("D1", []byte("secret"))
	_ = s.SetPushCert("topic", "2027")
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", err, info)
	}
	again, err := Open(dir)
	if err != nil || again.Topic() != "topic" || string(again.UnlockToken("D1")) != "secret" || !again.Enrolled("D1") {
		t.Fatalf("reload: %v", err)
	}
	view, _ := json.Marshal(again.View())
	if strings.Contains(string(view), "c2VjcmV0") || strings.Contains(string(view), "secret") {
		t.Error("the unlock token is in the view")
	}
	if !again.View().Devices[0].HasUnlock {
		t.Error("the view does not tell the unlock token exists")
	}
}

func TestLimits(t *testing.T) {
	s, _ := store(t)
	for i := 0; i < MaxCommands+10; i++ {
		_ = s.Sent(&Command{UUID: "C", UDID: "D"})
	}
	if n := len(s.View().Commands); n != MaxCommands {
		t.Errorf("commands kept: %d", n)
	}
}

func TestNamesAndSets(t *testing.T) {
	dir := t.TempDir()
	// a state file of a version that kept the name in the device: a device of a name only goes
	raw := `{"devices":{"A":{"udid":"A","name":"Old_A","enrolled_at":"2026-01-01T00:00:00Z"},"B":{"udid":"B","name":"Only_B"}}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Device("B"); ok || s.Name("B") != "Only_B" {
		t.Errorf("B: %q", s.Name("B"))
	}
	if d, ok := s.Device("A"); !ok || d.Name != "Old_A" {
		t.Errorf("A: %+v", d)
	}
	if err := s.SetName("A", "New_A"); err != nil {
		t.Fatal(err)
	}
	if v := s.View(); len(v.Devices) != 1 || v.Devices[0].Name != "New_A" {
		t.Errorf("view: %+v", v.Devices)
	}
	set := Set{Name: "Farm", Platform: "ios", Actions: []Action{{Kind: "preset", Name: "wifi", On: true, Params: map[string]string{"ssid": "LAB", "password": "x"}}}}
	if err := s.SaveSet(set); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSet(Set{Name: "Farm", Platform: "mac", Actions: set.Actions}); err == nil {
		t.Error("a set of another platform")
	}
	again, _ := Open(dir)
	if got := again.Sets(); len(got) != 1 || got[0].Actions[0].Params["password"] != "" || got[0].Actions[0].Params["ssid"] != "LAB" || again.Name("A") != "New_A" {
		t.Errorf("reopened: %+v %q", got, again.Name("A"))
	}
	if err := again.DeleteSet("ios", "Farm"); err != nil || len(again.Sets()) != 0 {
		t.Errorf("delete: %v", err)
	}
}
