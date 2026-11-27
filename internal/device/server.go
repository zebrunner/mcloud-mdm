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
	"sort"
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

// NodeHeader names the node of the token of a node call: the proxy of MCloud sets it from the answer of STF to its
// auth_request (the header of the client overwritten)
const NodeHeader = "X-MCloud-Node"

// nodeLabel: the labels of the nodes of STF
var nodeLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// Server is the handler of the device listener.
type Server struct {
	Config *config.Config
	SCEP   *scep.Server
	State  *state.Store
	Log    *slog.Logger
	// Android is nil without Headwind MDM
	Android *android.Manager
	// Commands sends the MDM commands of the nodes (the release of an iOS device): the admin server
	Commands Commander
	// Nodes knows the node of each device (STF): MDM_ENFORCE_NODE_BINDING
	Nodes NodeLookup
	tlsCA []byte
}

// NodeLookup returns the node a device is bound to (found is false for an unknown device).
type NodeLookup interface {
	DeviceNode(serial string) (node string, found bool, err error)
}

// Commander enqueues an MDM command for a device (NanoHUB pushes it) and returns its uuid; Enrolled applies the set of
// a new device.
type Commander interface {
	Send(udid, requestType string, args map[string]any) (string, error)
	Enrolled(platform, device string)
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

// Handler routes the devices (/scep, /android/agent.apk), the nodes (/mdm/enroll, /mdm/status, /mdm/release,
// /android/enroll, /android/status, /android/release: the enrollment token) and /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/scep", s.SCEP)
	mux.HandleFunc("GET /mdm/enroll", s.enroll)
	mux.HandleFunc("GET /mdm/status", s.iosStatus)
	mux.HandleFunc("POST /mdm/release", s.iosRelease)
	mux.HandleFunc("GET /android/status", s.androidStatus)
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
	if s.Config.EnforceNodeBinding && udid == "" {
		http.Error(w, "the udid is required", http.StatusBadRequest)
		return
	}
	if !s.boundToNode(w, r, udid) {
		return
	}
	topic := s.State.Topic()
	if topic == "" {
		http.Error(w, "no APNs push certificate: upload it in the admin UI first", http.StatusServiceUnavailable)
		return
	}
	subject := "mcloud-mdm-" + nanohub.NewUUID()[:8]
	if udid != "" {
		subject = scep.SubjectPrefix(udid) + nanohub.NewUUID()[:8]
	}
	// the challenge signs the identity of this subject (the server sets it, not the CSR) for the device and the node of
	// the call (the registry of the identities); with the binding of the nodes the CSR must be of the device too
	grant := scep.Grant{Subject: subject, UDID: udid, Bound: s.Config.EnforceNodeBinding}
	if node := r.Header.Get(NodeHeader); nodeLabel.MatchString(node) {
		grant.Node = node
	}
	challenge, err := s.SCEP.Challenges.Issue(grant)
	if err != nil {
		http.Error(w, "challenge failed", http.StatusInternalServerError)
		return
	}
	data, err := profile.Enrollment{
		ID: s.Config.ProfileID, OrgName: s.Config.OrgName, ServerURL: s.Config.PublicURL + "/mdm",
		SCEPURL: s.Config.SCEPURL, Topic: topic, Challenge: challenge, Subject: subject, TLSCA: s.tlsCA,
	}.Build()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// the name of the device on its host: the admin UI shows it
	if name := strings.TrimSpace(r.URL.Query().Get("name")); udid != "" && name != "" && len(name) <= 80 {
		if err := s.State.SetName(udid, name); err != nil {
			s.Log.Error("the name of the device not saved", "udid", udid, "err", err)
		}
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

// boundToNode checks with MDM_ENFORCE_NODE_BINDING that STF binds the device to the node of the call (NodeHeader);
// it answers the refusals (fail closed: no header, no answer of STF) and logs their reasons. Without the setting
// every node acts on every device, as before.
func (s *Server) boundToNode(w http.ResponseWriter, r *http.Request, device string) bool {
	if !s.Config.EnforceNodeBinding {
		return true
	}
	node := r.Header.Get(NodeHeader)
	refuse := func(reason string, args ...any) bool {
		s.Log.Warn("node call refused: "+reason, append([]any{"node", node, "device", device, "path", r.URL.Path,
			"remote", r.RemoteAddr}, args...)...)
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	switch {
	case node == "":
		s.Log.Error("node call refused: the proxy names no node ("+NodeHeader+"), MDM_ENFORCE_NODE_BINDING=true needs "+
			"an stf and an mcloud that pass it: update them or set MDM_ENFORCE_NODE_BINDING=false", "device", device,
			"path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	case !nodeLabel.MatchString(node):
		return refuse("not a node label")
	case s.Nodes == nil:
		return refuse("no STF (MDM_STF_URL)")
	}
	owner, found, err := s.Nodes.DeviceNode(device)
	if err != nil {
		s.Log.Error("node call refused: the node of the device not read from STF", "node", node, "device", device,
			"path", r.URL.Path, "err", err)
		http.Error(w, "the device is not checked, try again later", http.StatusServiceUnavailable)
		return false
	}
	if !found {
		return refuse("not a device of STF")
	}
	if owner != node {
		return refuse("the device is bound to another node", "bound_to", owner)
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
	if !s.boundToNode(w, r, serial) {
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
	s.Log.Info("android enrollment prepared", "serial", serial, "new", setup.New, "remote", r.RemoteAddr)
	if setup.New && s.Commands != nil {
		go s.Commands.Enrolled("android", serial)
	}
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
// secret is its token, the enrollment token protects it; with MDM_ENFORCE_NODE_BINDING only for a serial of the node
func (s *Server) androidRelease(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if s.Android == nil {
		http.Error(w, "no Android: HMDM_URL is not set", http.StatusNotFound)
		return
	}
	serial := r.URL.Query().Get("serial")
	if s.Config.EnforceNodeBinding && !android.ValidSerial(serial) {
		http.Error(w, "invalid serial", http.StatusBadRequest)
		return
	}
	if !s.boundToNode(w, r, serial) {
		return
	}
	s.Log.Info("android release command issued", "serial", serial, "remote", r.RemoteAddr)
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

// answer writes the answer of a node: JSON, or key=value lines with ?format=shell (the scripts of the nodes)
func answer(w http.ResponseWriter, r *http.Request, code int, fields [][2]string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("format") == "shell" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		for _, f := range fields {
			_, _ = fmt.Fprintf(w, "%s=%s\n", f[0], strings.NewReplacer("\n", " ", "\r", " ").Replace(f[1]))
		}
		return
	}
	out := map[string]string{}
	for _, f := range fields {
		out[f[0]] = f[1]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(out)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// iosStatus: what the webhook saw of the device, the device is not touched
func (s *Server) iosStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	udid := r.URL.Query().Get("udid")
	if !udidPattern.MatchString(udid) {
		http.Error(w, "invalid udid", http.StatusBadRequest)
		return
	}
	if !s.boundToNode(w, r, udid) {
		return
	}
	d, known := s.State.Device(udid)
	fields := [][2]string{{"udid", udid}, {"known", yesNo(known)}, {"enrolled", yesNo(s.State.Enrolled(udid))}}
	if known {
		fields = append(fields, [2]string{"checked_out", yesNo(d.CheckedOut)}, [2]string{"enrolled_at", d.EnrolledAt},
			[2]string{"last_seen_at", d.LastSeenAt}, [2]string{"product", d.Product}, [2]string{"os_version", d.OSVersion},
			[2]string{"serial", d.Serial}, [2]string{"unlock_token", yesNo(d.HasUnlock)})
	}
	answer(w, r, http.StatusOK, fields)
}

// iosRelease removes the enrollment profile by MDM (RemoveProfile): the device leaves MDM with every profile MDM
// installed; a supervised device stays supervised
func (s *Server) iosRelease(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	udid := r.URL.Query().Get("udid")
	if !udidPattern.MatchString(udid) {
		http.Error(w, "invalid udid", http.StatusBadRequest)
		return
	}
	if !s.boundToNode(w, r, udid) {
		return
	}
	if s.Commands == nil || !s.State.Enrolled(udid) {
		answer(w, r, http.StatusConflict, [][2]string{{"udid", udid}, {"error", "not an enrolled device"}})
		return
	}
	id, err := s.Commands.Send(udid, "RemoveProfile", map[string]any{"Identifier": s.Config.ProfileID})
	if err != nil {
		s.Log.Error("ios release failed", "udid", udid, "err", err)
		answer(w, r, http.StatusBadGateway, [][2]string{{"udid", udid}, {"error", err.Error()}})
		return
	}
	s.Log.Info("ios release sent", "udid", udid, "command", id, "remote", r.RemoteAddr)
	// the device leaves MDM: its identities renew no more (NanoHUB itself checks the CA only)
	if s.SCEP != nil && s.SCEP.Registry != nil {
		revoked, err := s.SCEP.Registry.RevokeUDID(udid, "released", "")
		if err != nil {
			s.Log.Error("the identities of the released device not revoked", "udid", udid, "err", err)
		}
		for _, x := range revoked {
			s.Log.Info("device identity revoked", "serial", x.Serial, "udid", udid, "reason", x.Reason)
		}
	}
	answer(w, r, http.StatusAccepted, [][2]string{{"udid", udid}, {"command", id}})
}

// androidStatus: what Headwind MDM knows of the device, the device is not touched
func (s *Server) androidStatus(w http.ResponseWriter, r *http.Request) {
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
	if !s.boundToNode(w, r, serial) {
		return
	}
	d, err := s.Android.Device(serial)
	if err != nil {
		answer(w, r, http.StatusBadGateway, [][2]string{{"serial", serial}, {"error", err.Error()}})
		return
	}
	fields := [][2]string{{"serial", serial}, {"known", yesNo(d != nil)}}
	if d != nil {
		var presets []string
		for name, on := range d.Presets {
			if on {
				presets = append(presets, name)
			}
		}
		sort.Strings(presets)
		fields = append(fields, [2]string{"device_owner", yesNo(d.Owner)}, [2]string{"last_sync_at", d.LastSyncAt},
			[2]string{"agent_version", d.Agent}, [2]string{"model", d.Model}, [2]string{"os_version", d.OSVersion},
			[2]string{"managed", yesNo(!d.Unmanaged)}, [2]string{"presets", strings.Join(presets, ",")})
	}
	answer(w, r, http.StatusOK, fields)
}
