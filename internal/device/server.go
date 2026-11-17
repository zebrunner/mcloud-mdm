// Package device serves the devices and the agents of the device hosts: SCEP, the enrollment profile and the
// health check. The proxy of MCloud publishes it; the admin UI is on another listener.
package device

import (
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/zebrunner/mcloud-mdm/internal/android"
	"github.com/zebrunner/mcloud-mdm/internal/config"
	"github.com/zebrunner/mcloud-mdm/internal/nanohub"
	"github.com/zebrunner/mcloud-mdm/internal/profile"
	"github.com/zebrunner/mcloud-mdm/internal/scep"
	"github.com/zebrunner/mcloud-mdm/internal/state"
)

// udidPattern: the UDIDs of the devices, the old 40 hex ones too
var udidPattern = regexp.MustCompile(`^[0-9A-Fa-f-]{20,64}$`)

// Server is the handler of the device listener.
type Server struct {
	Config *config.Config
	SCEP   *scep.Server
	State  *state.Store
	Log    *slog.Logger
	// Android is nil without Headwind MDM
	Android *android.Manager
	tlsCA   []byte
}

// New returns the server; the DER of MDM_TLS_CA_FILE is read once.
func New(c *config.Config, s *scep.Server, st *state.Store, log *slog.Logger) (*Server, error) {
	srv := &Server{Config: c, SCEP: s, State: st, Log: log}
	if c.TLSCAFile != "" {
		raw, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("MDM_TLS_CA_FILE %s: no PEM certificate", c.TLSCAFile)
		}
		srv.tlsCA = block.Bytes
	}
	return srv, nil
}

// Handler routes /scep, /mdm/enroll, /android/enroll, /android/release, /android/agent.apk and /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/scep", s.SCEP)
	mux.HandleFunc("GET /mdm/enroll", s.enroll)
	mux.HandleFunc("GET /android/enroll", s.androidEnroll)
	mux.HandleFunc("GET /android/release", s.androidRelease)
	mux.HandleFunc("GET /android/agent.apk", s.agentAPK)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}

// enroll returns an enrollment profile with a fresh one-time challenge to an agent with the enrollment token; the
// agent installs it over USB (go-ios, the supervision identity). The udid only names the device identity.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	udid := r.URL.Query().Get("udid")
	if udid != "" && !udidPattern.MatchString(udid) {
		http.Error(w, "invalid udid", http.StatusBadRequest)
		return
	}
	topic := s.State.Topic()
	if topic == "" {
		http.Error(w, "no APNs push certificate: upload it in the admin UI first", http.StatusServiceUnavailable)
		return
	}
	challenge, err := s.SCEP.Challenges.New()
	if err != nil {
		http.Error(w, "challenge failed", http.StatusInternalServerError)
		return
	}
	subject := "mcloud-mdm-" + nanohub.NewUUID()[:8]
	if udid != "" {
		subject = "mcloud-mdm-" + udid + "-" + nanohub.NewUUID()[:8]
	}
	data, err := profile.Enrollment{
		ID: s.Config.ProfileID, OrgName: s.Config.OrgName, ServerURL: s.Config.PublicURL + "/mdm",
		SCEPURL: s.Config.SCEPURL, Topic: topic, Challenge: challenge, Subject: subject, TLSCA: s.tlsCA,
	}.Build()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Log.Info("enrollment profile issued", "udid", udid, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// authorized checks the enrollment token of the agents of the device hosts
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.Config.EnrollToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcloud-mdm"`)
		http.Error(w, "the enrollment token is required", http.StatusUnauthorized)
		return false
	}
	return true
}

// androidEnroll prepares Headwind MDM for the device and returns the setup of its agent over adb (README.md#android)
func (s *Server) androidEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if s.Android == nil {
		http.Error(w, "no Android: HMDM_URL is not set", http.StatusNotFound)
		return
	}
	serial := r.URL.Query().Get("serial")
	if !android.ValidSerial(serial) {
		http.Error(w, "invalid serial", http.StatusBadRequest)
		return
	}
	agentURL := ""
	if _, err := os.Stat(s.Config.AgentAPK); err == nil {
		agentURL = s.Config.PublicURL + "/android/agent.apk"
	}
	setup, err := s.Android.Enroll(serial, r.URL.Query().Get("name"), agentURL)
	if err != nil {
		s.Log.Error("android enrollment failed", "serial", serial, "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.Log.Info("android enrollment prepared", "serial", serial, "remote", r.RemoteAddr)
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("format") == "shell" {
		// the setup command of the agent for adb shell, for the scripts without a JSON parser (android/enroll.sh)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(setup.Configure + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(setup)
}

// androidRelease returns the adb shell command that releases a device without the server (android/release.sh): the
// secret is its token, the enrollment token protects it
func (s *Server) androidRelease(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if s.Android == nil {
		http.Error(w, "no Android: HMDM_URL is not set", http.StatusNotFound)
		return
	}
	s.Log.Info("android release command issued", "serial", r.URL.Query().Get("serial"), "remote", r.RemoteAddr)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(s.Android.ReleaseCommand() + "\n"))
}

// agentAPK serves the Android agent: it is no secret, its signing key is
func (s *Server) agentAPK(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(s.Config.AgentAPK)
	if err != nil {
		http.Error(w, "no Android agent: MDM_ANDROID_AGENT_APK", http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	http.ServeContent(w, r, "mcloud-mdm-agent.apk", info.ModTime(), f)
}
