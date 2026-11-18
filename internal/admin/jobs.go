package admin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/android"
	"github.com/zebrunner/mcloud-mdm/internal/nanohub"
	"github.com/zebrunner/mcloud-mdm/internal/profile"
	"github.com/zebrunner/mcloud-mdm/internal/state"
)

// Limits of the jobs: the devices of a job run in parallel, the actions of a device one by one
const (
	MaxJobs        = 50
	MaxJobDevices  = 500
	MaxJobActions  = 50
	jobParallelism = 8
)

// Step statuses: waiting, running, then ok, queued (iOS: the device did not answer yet, it takes the command later),
// error
const (
	stepWaiting = "waiting"
	stepRunning = "running"
	stepOK      = "ok"
	stepQueued  = "queued"
	stepError   = "error"
	// a device the job did not reach: busy until the end of its window, or the job cancelled
	stepSkipped   = "skipped"
	stepCancelled = "cancelled"
)

// freePoll is the period of the checks of a device busy in STF
var freePoll = 30 * time.Second

// Step is an action of a job on one device.
type Step struct {
	Title  string `json:"title"`
	Status string `json:"status"`
	Output string `json:"output,omitempty"`
	// UUID is the iOS command of the step: its report is in the history
	UUID string `json:"uuid,omitempty"`
}

// Target is a device of a job with its steps.
type Target struct {
	Device string `json:"device"`
	Status string `json:"status"`
	// Note: why the device waits (busy in STF)
	Note  string  `json:"note,omitempty"`
	Steps []*Step `json:"steps"`
}

// JobOptions: StartAt delays the job, FreeOnly waits for each device until no user has it in STF, Until ends the
// waiting (the devices still busy are skipped).
type JobOptions struct {
	StartAt  time.Time
	Until    time.Time
	FreeOnly bool
}

// Job is a list of actions run on a list of devices of one platform.
type Job struct {
	ID         string    `json:"id"`
	Platform   string    `json:"platform"`
	Title      string    `json:"title"`
	CreatedAt  string    `json:"created_at"`
	StartAt    string    `json:"start_at,omitempty"`
	Until      string    `json:"until,omitempty"`
	FreeOnly   bool      `json:"free_only,omitempty"`
	FinishedAt string    `json:"finished_at,omitempty"`
	Cancelled  bool      `json:"cancelled,omitempty"`
	Targets    []*Target `json:"targets"`

	cancel chan struct{}
}

// jobs are the jobs of the admin UI, in memory: the newest first
type jobs struct {
	mu   sync.Mutex
	list []*Job
}

func (j *jobs) add(job *Job) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.list = append([]*Job{job}, j.list...)
	if len(j.list) > MaxJobs {
		j.list = j.list[:MaxJobs]
	}
}

// view is a deep copy of the jobs for the API
func (j *jobs) view() []Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Job, 0, len(j.list))
	for _, job := range j.list {
		c := *job
		c.Targets = make([]*Target, 0, len(job.Targets))
		for _, t := range job.Targets {
			tc := *t
			tc.Steps = make([]*Step, 0, len(t.Steps))
			for _, st := range t.Steps {
				sc := *st
				tc.Steps = append(tc.Steps, &sc)
			}
			c.Targets = append(c.Targets, &tc)
		}
		out = append(out, c)
	}
	return out
}

// update changes a step under the lock of the jobs
func (j *jobs) update(fn func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fn()
}

// stop cancels a job that did not finish: the devices not reached yet are skipped
func (j *jobs) stop(id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, job := range j.list {
		if job.ID == id {
			if job.FinishedAt != "" || job.Cancelled {
				return errors.New("the job is not running")
			}
			job.Cancelled = true
			close(job.cancel)
			return nil
		}
	}
	return fmt.Errorf("no job %q", id)
}

// actionTitle names an action in a job
func actionTitle(platform string, a state.Action) string {
	switch a.Kind {
	case "push":
		return "Push (wake up)"
	case "preset":
		title := a.Name
		if platform == "ios" {
			if p, ok := profile.FindPreset(a.Name); ok {
				title = p.Title
			}
		} else {
			for _, p := range android.Presets {
				if p.Name == a.Name {
					title = p.Title
				}
			}
		}
		if a.On {
			return title + ": on"
		}
		return title + ": off"
	default:
		if platform == "android" {
			for _, c := range android.Commands {
				if c.Name == a.Name {
					return c.Title
				}
			}
		}
		return a.Name
	}
}

// checkActions validates the actions of a job or a set before anything is sent
func (s *Server) checkActions(platform string, actions []state.Action) error {
	if platform != "ios" && platform != "android" {
		return errors.New("the platform: ios or android")
	}
	if platform == "android" && s.Android == nil {
		return errors.New("no Android: HMDM_URL is not set")
	}
	if len(actions) == 0 || len(actions) > MaxJobActions {
		return fmt.Errorf("1 to %d actions", MaxJobActions)
	}
	for _, a := range actions {
		switch a.Kind {
		case "preset":
			if platform == "ios" {
				if _, ok := profile.FindPreset(a.Name); !ok {
					return fmt.Errorf("no iOS preset %q", a.Name)
				}
			} else if !slices.ContainsFunc(android.Presets, func(p *android.Preset) bool { return p.Name == a.Name }) {
				return fmt.Errorf("no Android preset %q", a.Name)
			}
		case "command":
			if a.Name == "" {
				return errors.New("a command without its name")
			}
			if platform == "android" && !slices.ContainsFunc(android.Commands, func(c *android.Command) bool { return c.Name == a.Name }) {
				return fmt.Errorf("no Android command %q", a.Name)
			}
		case "push":
			if platform != "ios" {
				return errors.New("push is an iOS action")
			}
		default:
			return fmt.Errorf("unknown action %q: preset, command or push", a.Kind)
		}
	}
	return nil
}

// startJob runs the actions on the devices in the background and returns the job at once
func (s *Server) startJob(platform, title string, devices []string, actions []state.Action, opts JobOptions) (*Job, error) {
	if err := s.checkActions(platform, actions); err != nil {
		return nil, err
	}
	if opts.FreeOnly && s.STF == nil {
		return nil, errors.New("free devices only: no STF (MDM_STF_URL)")
	}
	if !opts.Until.IsZero() && (!opts.Until.After(time.Now()) || (!opts.StartAt.IsZero() && !opts.Until.After(opts.StartAt))) {
		return nil, errors.New("the end of the window is before its start or in the past")
	}
	var targets []*Target
	seen := map[string]bool{}
	for _, d := range devices {
		if d = strings.TrimSpace(d); d == "" || seen[d] {
			continue
		}
		seen[d] = true
		t := &Target{Device: d, Status: stepWaiting}
		for _, a := range actions {
			t.Steps = append(t.Steps, &Step{Title: actionTitle(platform, a), Status: stepWaiting})
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 || len(targets) > MaxJobDevices {
		return nil, fmt.Errorf("1 to %d devices", MaxJobDevices)
	}
	if title == "" {
		title = fmt.Sprintf("%d actions", len(actions))
		if len(actions) == 1 {
			title = actionTitle(platform, actions[0])
		}
	}
	job := &Job{ID: nanohub.NewUUID()[:8], Platform: platform, Title: title, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		FreeOnly: opts.FreeOnly, Targets: targets, cancel: make(chan struct{})}
	if !opts.StartAt.IsZero() {
		job.StartAt = opts.StartAt.UTC().Format(time.RFC3339)
	}
	if !opts.Until.IsZero() {
		job.Until = opts.Until.UTC().Format(time.RFC3339)
	}
	s.jobs.add(job)
	s.Log.Info("job started", "job", job.ID, "platform", platform, "title", title, "devices", len(targets), "actions", len(actions),
		"start_at", job.StartAt, "until", job.Until, "free_only", opts.FreeOnly)
	go func() {
		if d := time.Until(opts.StartAt); d > 0 {
			select {
			case <-time.After(d):
			case <-job.cancel:
			}
		}
		sem := make(chan struct{}, jobParallelism)
		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Add(1)
			go func(t *Target) {
				defer wg.Done()
				if !s.waitFree(job, t, opts) {
					return
				}
				select {
				case sem <- struct{}{}:
				case <-job.cancel:
					s.skip(t, stepCancelled, "")
					return
				}
				defer func() { <-sem }()
				s.runTarget(job, platform, t, actions)
			}(t)
		}
		wg.Wait()
		s.jobs.update(func() { job.FinishedAt = time.Now().UTC().Format(time.RFC3339) })
		s.Log.Info("job finished", "job", job.ID)
	}()
	return job, nil
}

// skip marks the device and its steps not run
func (s *Server) skip(t *Target, status, note string) {
	s.jobs.update(func() {
		t.Status, t.Note = status, note
		for _, st := range t.Steps {
			if st.Status == stepWaiting {
				st.Status = status
			}
		}
	})
}

// waitFree waits until the job may run on the device: not cancelled, and with FreeOnly present and free in STF
// (until the end of the window)
func (s *Server) waitFree(job *Job, t *Target, opts JobOptions) bool {
	for {
		select {
		case <-job.cancel:
			s.skip(t, stepCancelled, "")
			return false
		default:
		}
		if !opts.FreeOnly {
			return true
		}
		note := ""
		devices, err := s.STF.Devices()
		d, known := devices[t.Device]
		switch {
		case err != nil:
			note = "STF: " + err.Error()
		case !known:
			note = "not a device of STF"
		case !d.Present:
			note = "disconnected in STF"
		case d.Busy:
			note = "in use"
			if d.Owner != "" {
				note += " by " + d.Owner
			}
		default:
			s.jobs.update(func() { t.Note = "" })
			return true
		}
		if !opts.Until.IsZero() && time.Now().After(opts.Until) {
			s.skip(t, stepSkipped, note+": the window ended")
			return false
		}
		s.jobs.update(func() { t.Note = note + ", waiting" })
		select {
		case <-time.After(freePoll):
		case <-job.cancel:
			s.skip(t, stepCancelled, "")
			return false
		}
	}
}

// runTarget runs the actions on one device one by one; a failed action does not stop the next ones (they are
// independent settings); iOS refreshes the installed profiles once at the end
func (s *Server) runTarget(job *Job, platform string, t *Target, actions []state.Action) {
	s.jobs.update(func() { t.Status = stepRunning })
	profiles := false
	for i, a := range actions {
		select {
		case <-job.cancel:
			s.skip(t, stepCancelled, "")
			return
		default:
		}
		step := t.Steps[i]
		s.jobs.update(func() { step.Status = stepRunning })
		var status, output, uuid string
		if platform == "ios" {
			status, output, uuid = s.iosAction(t.Device, a)
			profiles = profiles || (a.Kind == "preset" && status != stepQueued && status != stepError)
		} else {
			status, output = s.androidAction(t.Device, a)
		}
		s.jobs.update(func() { step.Status, step.Output, step.UUID = status, output, uuid })
	}
	if profiles {
		if id, err := s.send(t.Device, "ProfileList", nil); err == nil {
			s.wait(id)
		}
	}
	s.jobs.update(func() {
		t.Status = stepOK
		for _, st := range t.Steps {
			if st.Status == stepError {
				t.Status = stepError
				return
			}
			if st.Status == stepQueued {
				t.Status = stepQueued
			}
		}
	})
}

// answer turns the status of an iOS command into the status of a step
func answer(status string) string {
	switch status {
	case "Acknowledged":
		return stepOK
	case "Queued", "NotNow":
		return stepQueued
	default:
		return stepError
	}
}

func (s *Server) iosAction(udid string, a state.Action) (status, output, uuid string) {
	switch a.Kind {
	case "push":
		if err := s.Push(udid); err != nil {
			return stepError, err.Error(), ""
		}
		return stepOK, "", ""
	case "preset":
		p, _ := profile.FindPreset(a.Name)
		if a.On {
			// a saved set has no password: the UI asks for it (empty for an open network), the job never guesses
			if _, given := a.Params["password"]; slices.Contains(p.Params, "password") && !given {
				return stepError, "the password is not stored: apply it from the admin UI, it asks for the password", ""
			}
			return s.installPreset(udid, p, a.Params)
		}
		return s.removePreset(udid, p)
	default:
		args := map[string]any{}
		for k, v := range a.Args {
			args[k] = v
		}
		id, err := s.send(udid, a.Name, args)
		if err != nil {
			return stepError, err.Error(), ""
		}
		st := s.wait(id)
		out := st
		if st == "Queued" {
			out = "no answer yet: the device takes it when it connects"
		}
		return answer(st), out, id
	}
}

// installPreset sends the commands of the preset, then its profile, each after the answer to the previous one
func (s *Server) installPreset(udid string, p *profile.Preset, params map[string]string) (status, output, uuid string) {
	data, err := p.Build(s.Config.OrgName, params)
	if err != nil {
		return stepError, err.Error(), ""
	}
	var steps []string
	for _, c := range p.Before {
		id, err := s.send(udid, c.RequestType, c.Args)
		if err != nil {
			return stepError, err.Error(), ""
		}
		st := s.wait(id)
		steps = append(steps, c.RequestType+": "+st)
		if answer(st) == stepError {
			return stepError, strings.Join(steps, "\n"), id
		}
	}
	id, err := s.send(udid, "InstallProfile", map[string]any{"Payload": map[string]any{"$data": base64.StdEncoding.EncodeToString(data)}})
	if err != nil {
		return stepError, err.Error(), ""
	}
	st := s.wait(id)
	steps = append(steps, "InstallProfile "+p.ID+": "+st)
	if st == "Queued" {
		steps = append(steps, "no answer: the device did not connect (network?), do not install again before it does")
	}
	return answer(st), strings.Join(steps, "\n"), id
}

func (s *Server) removePreset(udid string, p *profile.Preset) (status, output, uuid string) {
	id, err := s.send(udid, "RemoveProfile", map[string]any{"Identifier": p.ID})
	if err != nil {
		return stepError, err.Error(), ""
	}
	st := s.wait(id)
	return answer(st), "RemoveProfile: " + st, id
}

func (s *Server) androidAction(serial string, a state.Action) (status, output string) {
	var err error
	if a.Kind == "preset" {
		err = s.Android.SetPreset(serial, a.Name, a.On)
	} else {
		err = s.Android.Send(serial, a.Name, a.Params)
	}
	if err != nil {
		return stepError, err.Error()
	}
	if a.Kind == "preset" {
		return stepOK, "saved: Headwind MDM pushes it, the device applies it at its sync"
	}
	return stepOK, "sent (MQTT): the device log shows its delivery"
}

// actions decodes the actions of a request body
func actions(body map[string]any) ([]state.Action, error) {
	list, _ := body["actions"].([]any)
	out := make([]state.Action, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("an action is not an object")
		}
		a := state.Action{Kind: str(m, "kind"), Name: str(m, "name")}
		a.On, _ = m["on"].(bool)
		if raw, ok := m["params"].(map[string]any); ok {
			a.Params = map[string]string{}
			for k, v := range raw {
				switch x := v.(type) {
				case string:
					a.Params[k] = x
				case bool:
					if x {
						a.Params[k] = "1"
					}
				}
			}
		}
		a.Args, _ = m["args"].(map[string]any)
		out = append(out, a)
	}
	return out, nil
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) jobsView(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, s.jobs.view())
}

// jobStart: {platform, title, devices: [...], actions: [...]}
func (s *Server) jobStart(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	list, err := actions(body)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	var opts JobOptions
	opts.FreeOnly, _ = body["free_only"].(bool)
	for key, at := range map[string]*time.Time{"start_at": &opts.StartAt, "until": &opts.Until} {
		if v := str(body, key); v != "" {
			if *at, err = time.Parse(time.RFC3339, v); err != nil {
				fail(w, http.StatusBadRequest, fmt.Errorf("%s: an RFC 3339 time", key))
				return
			}
		}
	}
	job, err := s.startJob(str(body, "platform"), str(body, "title"), stringList(body["devices"]), list, opts)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"id": job.ID})
}

// setSave: {platform, name, actions: [...]}; the password of a preset is never stored
func (s *Server) setSave(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	list, err := actions(body)
	if err == nil {
		err = s.checkActions(str(body, "platform"), list)
	}
	if err == nil {
		err = s.State.SaveSet(state.Set{Name: str(body, "name"), Platform: str(body, "platform"), Actions: list})
	}
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("set saved", "platform", str(body, "platform"), "name", str(body, "name"), "actions", len(list))
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setDelete(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if err := s.State.DeleteSet(str(body, "platform"), str(body, "name")); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("set deleted", "platform", str(body, "platform"), "name", str(body, "name"))
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) jobCancel(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if err := s.jobs.stop(str(body, "id")); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("job cancelled", "job", str(body, "id"))
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

// setsView: the saved sets and the sets assigned to the devices
func (s *Server) setsAll(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, map[string]any{"sets": s.State.Sets(), "assigned": s.State.Assigned()})
}

// setAssign: {platform, name, devices}; an empty name removes the sets of the devices
func (s *Server) setAssign(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	devices := stringList(body["devices"])
	if len(devices) == 0 {
		fail(w, http.StatusBadRequest, errors.New("no device"))
		return
	}
	if err := s.State.Assign(str(body, "platform"), str(body, "name"), devices); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("set assigned", "platform", str(body, "platform"), "name", str(body, "name"), "devices", len(devices))
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

// setDefault: {platform, name}; an empty name: no default set
func (s *Server) setDefault(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if err := s.State.SetDefault(str(body, "platform"), str(body, "name")); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("default set", "platform", str(body, "platform"), "name", str(body, "name"))
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

// Enrolled applies the set of a device enrolled anew (iOS: after its TokenUpdate, Android: a new device of Headwind
// MDM): its assigned set, else the default set of the platform, which becomes its set
func (s *Server) Enrolled(platform, device string) {
	set, assigned, ok := s.State.SetOf(platform, device)
	if !ok {
		return
	}
	if !assigned {
		if err := s.State.Assign(platform, set.Name, []string{device}); err != nil {
			s.Log.Error("default set not assigned", "device", device, "err", err)
		}
	}
	if _, err := s.startJob(platform, fmt.Sprintf("Set %q (enrollment)", set.Name), []string{device}, set.Actions, JobOptions{}); err != nil {
		s.Log.Error("the set of the enrollment not applied", "device", device, "set", set.Name, "err", err)
	}
}

// farm: the devices of STF (names, nodes, locations, users) by serial
func (s *Server) farm(w http.ResponseWriter, _ *http.Request) {
	if s.STF == nil {
		reply(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	devices, err := s.STF.Devices()
	view := map[string]any{"enabled": true, "devices": devices}
	if err != nil {
		view["error"] = err.Error()
	}
	reply(w, http.StatusOK, view)
}
