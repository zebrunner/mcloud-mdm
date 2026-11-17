package admin

import (
	"errors"
	"net/http"
	"os"

	"github.com/zebrunner/mcloud-mdm/internal/android"
)

// androidView: the Android devices of Headwind MDM, the presets and the commands; enabled=false without HMDM_URL
func (s *Server) androidView(w http.ResponseWriter, _ *http.Request) {
	if s.Android == nil {
		reply(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	view := map[string]any{"enabled": true, "presets": android.Presets, "commands": android.Commands,
		"server": s.Config.HeadwindPublicURL, "enroll_url": s.Config.PublicURL + "/android/enroll"}
	if _, err := os.Stat(s.Config.AgentAPK); err == nil {
		view["agent_url"] = s.Config.PublicURL + "/android/agent.apk"
	}
	devices, err := s.Android.Devices()
	if err != nil {
		view["error"] = err.Error()
	}
	view["devices"] = devices
	view["history"] = s.Android.History()
	reply(w, http.StatusOK, view)
}

func (s *Server) androidEnabled(w http.ResponseWriter) bool {
	if s.Android == nil {
		fail(w, http.StatusNotFound, errors.New("no Android: HMDM_URL is not set"))
		return false
	}
	return true
}

func (s *Server) androidEnroll(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if !s.androidEnabled(w) {
		return
	}
	setup, err := s.Android.Enroll(str(body, "serial"), str(body, "name"), "")
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("android enrollment prepared", "serial", setup.Serial)
	reply(w, http.StatusOK, setup)
}

func (s *Server) androidPreset(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if !s.androidEnabled(w) {
		return
	}
	on, _ := body["on"].(bool)
	if err := s.Android.SetPreset(str(body, "serial"), str(body, "name"), on); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("android preset", "serial", str(body, "serial"), "preset", str(body, "name"), "on", on)
	reply(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) androidCommand(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if !s.androidEnabled(w) {
		return
	}
	args := map[string]string{}
	if raw, ok := body["args"].(map[string]any); ok {
		for k, v := range raw {
			switch x := v.(type) {
			case string:
				args[k] = x
			case bool:
				if x {
					args[k] = "1"
				}
			}
		}
	}
	if err := s.Android.Send(str(body, "serial"), str(body, "name"), args); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("android command", "serial", str(body, "serial"), "command", str(body, "name"))
	reply(w, http.StatusOK, map[string]any{"ok": true})
}

// androidLog: the device log of the agent, the answers of the commands
func (s *Server) androidLog(w http.ResponseWriter, r *http.Request) {
	if !s.androidEnabled(w) {
		return
	}
	records, err := s.Android.Log(r.URL.Query().Get("serial"), 200)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	reply(w, http.StatusOK, records)
}

func (s *Server) androidDelete(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if !s.androidEnabled(w) {
		return
	}
	if err := s.Android.Delete(str(body, "serial")); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("android device deleted", "serial", str(body, "serial"))
	reply(w, http.StatusOK, map[string]any{"ok": true})
}
