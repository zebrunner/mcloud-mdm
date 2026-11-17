// Package admin serves the admin UI, its API and the webhook of NanoHUB. It is never published by the proxy without
// the authentication of MCloud: it sends any MDM command to any device.
package admin

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/android"
	"github.com/zebrunner/mcloud-mdm/internal/config"
	"github.com/zebrunner/mcloud-mdm/internal/nanohub"
	"github.com/zebrunner/mcloud-mdm/internal/profile"
	"github.com/zebrunner/mcloud-mdm/internal/state"
)

//go:embed web/index.html web/catalog.json
var web embed.FS

// Server is the handler of the admin listener.
type Server struct {
	Config  *config.Config
	NanoHUB *nanohub.Client
	State   *state.Store
	Log     *slog.Logger
	// Android is nil without Headwind MDM
	Android *android.Manager
	// AnswerTimeout bounds the wait for the report of a command of a ready profile
	AnswerTimeout time.Duration
	// RefreshDelay is the wait after a new enrollment before its DDM notify and ProfileList
	RefreshDelay time.Duration
}

// Handler routes the UI, the API and the webhook.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.static("web/index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /api/catalog", s.static("web/catalog.json", "application/json"))
	mux.HandleFunc("GET /api/presets", s.presets)
	mux.HandleFunc("GET /api/state", s.stateView)
	mux.HandleFunc("POST /api/command", s.browser(s.command))
	mux.HandleFunc("POST /api/push", s.browser(s.push))
	mux.HandleFunc("POST /api/preset/install", s.browser(s.presetInstall))
	mux.HandleFunc("POST /api/preset/remove", s.browser(s.presetRemove))
	mux.HandleFunc("POST /api/pushcert", s.browser(s.pushCert))
	mux.HandleFunc("POST /api/raw", s.browser(s.raw))
	mux.HandleFunc("GET /api/android", s.androidView)
	mux.HandleFunc("POST /api/android/enroll", s.browser(s.androidEnroll))
	mux.HandleFunc("POST /api/android/preset", s.browser(s.androidPreset))
	mux.HandleFunc("POST /api/android/command", s.browser(s.androidCommand))
	mux.HandleFunc("POST /api/android/delete", s.browser(s.androidDelete))
	mux.HandleFunc("POST /webhook", s.webhook)
	return mux
}

func (s *Server) static(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		data, err := web.ReadFile(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

func reply(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, code int, err error) {
	reply(w, code, map[string]string{"error": err.Error()})
}

// browser accepts the POST of the page itself only: a JSON body and no Origin of another site (CSRF)
func (s *Server) browser(next func(http.ResponseWriter, *http.Request, map[string]any)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
				fail(w, http.StatusForbidden, errors.New("foreign origin"))
				return
			}
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(w, http.StatusUnsupportedMediaType, errors.New("a JSON body is required"))
			return
		}
		var body map[string]any
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		next(w, r, body)
	}
}

func str(body map[string]any, key string) string {
	v, _ := body[key].(string)
	return v
}

func (s *Server) presets(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, profile.Presets)
}

// installed are the identifiers of the profiles of every device from its last ProfileList answered after its last
// enrollment change (iOS removes the MDM profiles with the MDM profile)
func installed(v state.View) map[string]any {
	changed := map[string]string{}
	for _, d := range v.Devices {
		changed[d.UDID] = d.ChangedAt
	}
	out := map[string]any{}
	for _, c := range v.Commands {
		if !strings.HasPrefix(c.Type, "ProfileList") || c.Status != "Acknowledged" {
			continue
		}
		if _, seen := out[c.UDID]; seen {
			continue
		}
		stale := changed[c.UDID] > c.AnsweredAt
		var ids []string
		if report, ok := c.Report.(map[string]any); ok && !stale {
			list, _ := report["ProfileList"].([]any)
			for _, p := range list {
				if pm, ok := p.(map[string]any); ok {
					if id, ok := pm["PayloadIdentifier"].(string); ok {
						ids = append(ids, id)
					}
				}
			}
		}
		out[c.UDID] = map[string]any{"at": c.AnsweredAt, "stale": stale, "ids": ids}
	}
	return out
}

func (s *Server) stateView(w http.ResponseWriter, _ *http.Request) {
	v := s.State.View()
	reply(w, http.StatusOK, map[string]any{
		"server": map[string]any{
			"mdm_url": s.Config.PublicURL + "/mdm", "scep_url": s.Config.SCEPURL,
			"enroll_url": s.Config.PublicURL + "/mdm/enroll", "topic": v.Topic, "push_not_after": v.PushNotAfter,
		},
		"devices": v.Devices, "commands": v.Commands, "events": v.Events, "profiles": installed(v),
	})
}

// send enqueues a command of the UI; ClearPasscode gets the unlock token of the device
func (s *Server) send(udid, requestType string, args map[string]any) (string, error) {
	if !s.State.Enrolled(udid) {
		return "", fmt.Errorf("%s is not an enrolled device", udid)
	}
	// the catalog has presets of one request type: "Settings: TimeZone" is Settings
	requestType = strings.TrimSpace(strings.SplitN(requestType, ":", 2)[0])
	if args == nil {
		args = map[string]any{}
	}
	if requestType == "ClearPasscode" {
		if _, ok := args["UnlockToken"]; !ok {
			token := s.State.UnlockToken(udid)
			if token == nil {
				return "", errors.New("no UnlockToken of the device: it did not send one at its enrollment")
			}
			args["UnlockToken"] = map[string]any{"$data": base64.StdEncoding.EncodeToString(token)}
		}
	}
	id, cmd, err := nanohub.NewCommand(requestType, args)
	if err != nil {
		return "", err
	}
	shown := map[string]any{}
	for k, v := range args {
		if k == "UnlockToken" || k == "Payload" {
			v = "<data>"
		}
		shown[k] = v
	}
	status, body, err := s.NanoHUB.Enqueue(udid, cmd)
	if err != nil {
		return "", err
	}
	if status/100 != 2 {
		return "", fmt.Errorf("NanoHUB: %d %s", status, strings.TrimSpace(string(body)))
	}
	var enqueue any = string(body)
	_ = json.Unmarshal(body, &enqueue)
	return id, s.State.Sent(&state.Command{UUID: id, UDID: udid, Type: requestType, Args: shown, Enqueue: enqueue})
}

// wait returns the status of the command once the device answered, Queued after the timeout
func (s *Server) wait(uuid string) string {
	deadline := time.Now().Add(s.AnswerTimeout)
	for time.Now().Before(deadline) {
		if status := s.State.Status(uuid); status != "Queued" {
			return status
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "Queued"
}

func (s *Server) command(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	args, _ := body["args"].(map[string]any)
	id, err := s.send(str(body, "udid"), str(body, "type"), args)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"uuid": id})
}

func (s *Server) push(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	status, data, err := s.NanoHUB.Push(str(body, "udid"))
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"status": status, "response": string(data)})
}

func (s *Server) presetInstall(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	udid := str(body, "udid")
	p, ok := profile.FindPreset(str(body, "name"))
	if !ok {
		fail(w, http.StatusBadRequest, errors.New("unknown preset"))
		return
	}
	params := map[string]string{}
	if raw, ok := body["params"].(map[string]any); ok {
		for k, v := range raw {
			params[k], _ = v.(string)
		}
	}
	data, err := p.Build(s.Config.OrgName, params)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	var steps []string
	// one by one, each after the answer to the previous one
	for _, c := range p.Before {
		id, err := s.send(udid, c.RequestType, c.Args)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		steps = append(steps, c.RequestType+": "+s.wait(id))
	}
	id, err := s.send(udid, "InstallProfile", map[string]any{"Payload": map[string]any{"$data": base64.StdEncoding.EncodeToString(data)}})
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	status := s.wait(id)
	steps = append(steps, "InstallProfile "+p.ID+": "+status)
	if status == "Queued" {
		steps = append(steps, "no answer: the device did not connect (network?), do not install again before it does")
	} else if refresh, err := s.send(udid, "ProfileList", nil); err == nil {
		steps = append(steps, "ProfileList: "+s.wait(refresh))
	}
	reply(w, http.StatusOK, map[string]string{"output": strings.Join(steps, "\n"), "uuid": id})
}

func (s *Server) presetRemove(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	udid := str(body, "udid")
	p, ok := profile.FindPreset(str(body, "name"))
	if !ok {
		fail(w, http.StatusBadRequest, errors.New("unknown preset"))
		return
	}
	id, err := s.send(udid, "RemoveProfile", map[string]any{"Identifier": p.ID})
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	status := s.wait(id)
	output := "RemoveProfile: " + status
	if status != "Queued" {
		if refresh, err := s.send(udid, "ProfileList", nil); err == nil {
			output += "\nProfileList: " + s.wait(refresh)
		}
	}
	reply(w, http.StatusOK, map[string]string{"output": output, "uuid": id})
}

// pushCert uploads the push certificate and its key (one PEM text) to NanoHUB and keeps the topic of the profiles
func (s *Server) pushCert(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	pemText := str(body, "pem")
	if !strings.Contains(pemText, "CERTIFICATE") || !strings.Contains(pemText, "PRIVATE KEY") {
		fail(w, http.StatusBadRequest, errors.New("the PEM of the push certificate and of its private key are required"))
		return
	}
	topic, notAfter, err := s.NanoHUB.PushCert([]byte(pemText))
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	if err := s.State.SetPushCert(topic, notAfter); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	s.Log.Info("push certificate uploaded", "topic", topic, "not_after", notAfter)
	reply(w, http.StatusOK, map[string]string{"topic": topic, "not_after": notAfter})
}

// raw is the console of the API of NanoHUB (DDM, NanoCMD, NanoMDM)
func (s *Server) raw(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	path := str(body, "path")
	method := strings.ToUpper(str(body, "method"))
	if !(strings.HasPrefix(path, "/api/v1/") || path == "/version") || strings.Contains(path, "..") {
		fail(w, http.StatusBadRequest, errors.New("the path must start with /api/v1/"))
		return
	}
	switch method {
	case http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete:
	default:
		fail(w, http.StatusBadRequest, errors.New("GET, PUT, POST or DELETE"))
		return
	}
	status, data, err := s.NanoHUB.Do(method, path, []byte(str(body, "body")))
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"status": status, "response": string(data)})
}
