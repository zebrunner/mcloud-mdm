// Package state keeps what the admin UI shows: the commands with the reports of the devices, the check-in events and
// the devices, from the webhook of NanoHUB; it is a JSON file of the data directory (mode 600: it has the unlock
// tokens of the devices).
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Limits of the history kept
const (
	MaxCommands = 500
	MaxEvents   = 500
)

// Command is a command sent to a device and its report.
type Command struct {
	UUID       string `json:"uuid"`
	UDID       string `json:"udid"`
	Type       string `json:"type"`
	SentAt     string `json:"sent_at"`
	Status     string `json:"status"`
	AnsweredAt string `json:"answered_at,omitempty"`
	Args       any    `json:"args,omitempty"`
	Report     any    `json:"report,omitempty"`
	Enqueue    any    `json:"enqueue,omitempty"`
}

// Event is a check-in or a report of a device.
type Event struct {
	At     string `json:"at"`
	UDID   string `json:"udid"`
	Event  string `json:"event"`
	Detail any    `json:"detail,omitempty"`
}

// Device is an enrollment seen by the webhook.
type Device struct {
	UDID       string `json:"udid"`
	Serial     string `json:"serial,omitempty"`
	Product    string `json:"product,omitempty"`
	OSVersion  string `json:"os_version,omitempty"`
	EnrolledAt string `json:"enrolled_at,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	CheckedOut bool   `json:"checked_out"`
	HasUnlock  bool   `json:"unlock_token"`
	ChangedAt  string `json:"enrollment_changed_at,omitempty"`
}

// Data is the content of the file.
type Data struct {
	Commands     []*Command         `json:"commands"`
	Events       []*Event           `json:"events"`
	Devices      map[string]*Device `json:"devices"`
	Topic        string             `json:"topic,omitempty"`
	PushNotAfter string             `json:"push_not_after,omitempty"`
	// the unlock tokens of the devices (ClearPasscode), never shown by the API
	UnlockTokens map[string][]byte `json:"unlock_tokens,omitempty"`
}

// Store is the state with its file.
type Store struct {
	mu   sync.Mutex
	path string
	data Data
	Now  func() time.Time
}

// Open reads the state of dir/state.json or starts an empty one.
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "state.json"), Now: time.Now}
	raw, err := os.ReadFile(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, err
		}
	}
	if s.data.Devices == nil {
		s.data.Devices = map[string]*Device{}
	}
	if s.data.UnlockTokens == nil {
		s.data.UnlockTokens = map[string][]byte{}
	}
	return s, nil
}

func (s *Store) now() string { return s.Now().Format(time.RFC3339) }

// save writes the file atomically; the caller holds the lock
func (s *Store) save() error {
	if len(s.data.Commands) > MaxCommands {
		s.data.Commands = s.data.Commands[len(s.data.Commands)-MaxCommands:]
	}
	if len(s.data.Events) > MaxEvents {
		s.data.Events = s.data.Events[len(s.data.Events)-MaxEvents:]
	}
	raw, err := json.MarshalIndent(&s.data, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) device(udid string) *Device {
	d, ok := s.data.Devices[udid]
	if !ok {
		d = &Device{UDID: udid}
		s.data.Devices[udid] = d
	}
	return d
}

func (s *Store) event(udid, name string, detail any) {
	s.data.Events = append(s.data.Events, &Event{At: s.now(), UDID: udid, Event: name, Detail: detail})
}

// Sent records a command sent through the UI.
func (s *Store) Sent(c *Command) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.SentAt, c.Status = s.now(), "Queued"
	s.data.Commands = append(s.data.Commands, c)
	return s.save()
}

// Answered records the report of a command; a command not sent through the UI (DDM, NanoCMD, CLI) is added with
// requestType.
func (s *Store) Answered(udid, uuid, status, requestType string, report any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.device(udid)
	d.LastSeenAt = s.now()
	if uuid == "" {
		s.event(udid, "Connect "+status, nil)
		return s.save()
	}
	var c *Command
	for i := len(s.data.Commands) - 1; i >= 0; i-- {
		if s.data.Commands[i].UUID == uuid {
			c = s.data.Commands[i]
			break
		}
	}
	if c == nil {
		c = &Command{UUID: uuid, UDID: udid, Type: requestType + " (outside the UI)"}
		s.data.Commands = append(s.data.Commands, c)
	}
	c.Status, c.AnsweredAt, c.Report = status, s.now(), report
	short := uuid
	if len(short) > 8 {
		short = short[:8]
	}
	s.event(udid, "Connect "+status+" "+short, nil)
	return s.save()
}

// Authenticate records the start of an enrollment: NanoMDM clears the queue of the device then, so its waiting
// commands are Cleared.
func (s *Store) Authenticate(udid, serial, product, osVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.device(udid)
	d.Serial, d.Product, d.OSVersion = serial, product, osVersion
	d.ChangedAt, d.LastSeenAt = s.now(), s.now()
	s.clear(udid)
	s.event(udid, "Authenticate", map[string]string{"serial": serial, "product": product, "os_version": osVersion})
	return s.save()
}

// TokenUpdate records the end of an enrollment (and the token updates after it); it keeps the unlock token when the
// device sends one, and reports whether the device was not enrolled (a new enrollment).
func (s *Store) TokenUpdate(udid string, unlockToken []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.device(udid)
	enrolled := d.EnrolledAt == "" || d.CheckedOut || d.ChangedAt > d.EnrolledAt
	if enrolled {
		d.EnrolledAt = s.now()
	}
	d.CheckedOut, d.LastSeenAt = false, s.now()
	if len(unlockToken) > 0 {
		s.data.UnlockTokens[udid] = unlockToken
	}
	s.event(udid, "TokenUpdate", nil)
	return enrolled, s.save()
}

// CheckOut records the removal of the MDM profile: iOS removes every MDM profile with it.
func (s *Store) CheckOut(udid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.device(udid)
	d.CheckedOut, d.ChangedAt, d.LastSeenAt = true, s.now(), s.now()
	s.clear(udid)
	s.event(udid, "CheckOut", nil)
	return s.save()
}

// Event records another event of a device (e.g. DeclarativeManagement).
func (s *Store) Event(udid, name string, detail any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.device(udid).LastSeenAt = s.now()
	s.event(udid, name, detail)
	return s.save()
}

func (s *Store) clear(udid string) {
	for _, c := range s.data.Commands {
		if c.UDID == udid && c.Status == "Queued" {
			c.Status, c.AnsweredAt = "Cleared", s.now()
		}
	}
}

// SetPushCert records the topic and the expiry of the uploaded push certificate.
func (s *Store) SetPushCert(topic, notAfter string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Topic, s.data.PushNotAfter = topic, notAfter
	return s.save()
}

// Topic is the push topic of the enrollment profiles, empty before the push certificate.
func (s *Store) Topic() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Topic
}

// UnlockToken of the device, nil without one.
func (s *Store) UnlockToken(udid string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.UnlockTokens[udid]
}

// Enrolled reports whether the device is enrolled now.
func (s *Store) Enrolled(udid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.data.Devices[udid]
	return ok && d.EnrolledAt != "" && !d.CheckedOut
}

// Device returns a copy of the device of the udid, false when the webhook never saw it.
func (s *Store) Device(udid string) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.data.Devices[udid]
	if !ok {
		return Device{}, false
	}
	c := *d
	c.HasUnlock = len(s.data.UnlockTokens[udid]) > 0
	return c, true
}

// Status of a command, "" when unknown.
func (s *Store) Status(uuid string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.data.Commands) - 1; i >= 0; i-- {
		if s.data.Commands[i].UUID == uuid {
			return s.data.Commands[i].Status
		}
	}
	return ""
}

// View is the state the API shows: the newest first, no unlock token.
type View struct {
	Commands     []Command `json:"commands"`
	Events       []Event   `json:"events"`
	Devices      []Device  `json:"devices"`
	Topic        string    `json:"topic,omitempty"`
	PushNotAfter string    `json:"push_not_after,omitempty"`
}

// View returns a copy of the state.
func (s *Store) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{Topic: s.data.Topic, PushNotAfter: s.data.PushNotAfter}
	for i := len(s.data.Commands) - 1; i >= 0; i-- {
		v.Commands = append(v.Commands, *s.data.Commands[i])
	}
	for i := len(s.data.Events) - 1; i >= 0; i-- {
		v.Events = append(v.Events, *s.data.Events[i])
	}
	for _, d := range s.data.Devices {
		c := *d
		c.HasUnlock = len(s.data.UnlockTokens[d.UDID]) > 0
		v.Devices = append(v.Devices, c)
	}
	return v
}
