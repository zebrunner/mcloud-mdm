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
)

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
	Device string  `json:"device"`
	Status string  `json:"status"`
	Steps  []*Step `json:"steps"`
}

// Job is a list of actions run on a list of devices of one platform.
type Job struct {
	ID         string    `json:"id"`
	Platform   string    `json:"platform"`
	Title      string    `json:"title"`
	CreatedAt  string    `json:"created_at"`
	FinishedAt string    `json:"finished_at,omitempty"`
	Targets    []*Target `json:"targets"`
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
func (s *Server) startJob(platform, title string, devices []string, actions []state.Action) (*Job, error) {
	if err := s.checkActions(platform, actions); err != nil {
		return nil, err
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
	job := &Job{ID: nanohub.NewUUID()[:8], Platform: platform, Title: title, CreatedAt: time.Now().UTC().Format(time.RFC3339), Targets: targets}
	s.jobs.add(job)
	s.Log.Info("job started", "job", job.ID, "platform", platform, "title", title, "devices", len(targets), "actions", len(actions))
	go func() {
		sem := make(chan struct{}, jobParallelism)
		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func(t *Target) {
				defer func() { <-sem; wg.Done() }()
				s.runTarget(platform, t, actions)
			}(t)
		}
		wg.Wait()
		s.jobs.update(func() { job.FinishedAt = time.Now().UTC().Format(time.RFC3339) })
		s.Log.Info("job finished", "job", job.ID)
	}()
	return job, nil
}

// runTarget runs the actions on one device one by one; a failed action does not stop the next ones (they are
// independent settings); iOS refreshes the installed profiles once at the end
func (s *Server) runTarget(platform string, t *Target, actions []state.Action) {
	s.jobs.update(func() { t.Status = stepRunning })
	profiles := false
	for i, a := range actions {
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
	job, err := s.startJob(str(body, "platform"), str(body, "title"), stringList(body["devices"]), list)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"id": job.ID})
}

func (s *Server) setsView(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, s.State.Sets())
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
