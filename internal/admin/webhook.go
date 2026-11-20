package admin

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"howett.net/plist"
)

// event is the webhook of NanoMDM (the format of MicroMDM): topic, and the event with the raw plist of the device
type event struct {
	Topic   string     `json:"topic"`
	Ack     *eventBody `json:"acknowledge_event"`
	Checkin *eventBody `json:"checkin_event"`
}

type eventBody struct {
	UDID        string `json:"udid"`
	Enrollment  string `json:"enrollment_id"`
	Status      string `json:"status"`
	CommandUUID string `json:"command_uuid"`
	RawPayload  string `json:"raw_payload"`
}

// reportTypes guesses the request type of a command sent outside the UI by its report
var reportTypes = []string{"ProfileList", "QueryResponses:DeviceInformation", "SecurityInfo", "CertificateList",
	"InstalledApplicationList", "ProvisioningProfileList", "GlobalRestrictions:Restrictions", "AvailableOSUpdates",
	"OSUpdateStatus", "ManagedApplicationList"}

func guessType(report map[string]any) string {
	for _, rt := range reportTypes {
		key, name, _ := strings.Cut(rt, ":")
		if name == "" {
			name = key
		}
		if _, ok := report[key]; ok {
			return name
		}
	}
	return "command"
}

// jsonValue makes a report showable: data is replaced by its size (a small one is kept in base64)
func jsonValue(v any) any {
	switch t := v.(type) {
	case []byte:
		out := map[string]any{"$data_bytes": len(t)}
		if len(t) <= 4096 {
			out["$base64"] = base64.StdEncoding.EncodeToString(t)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, item := range t {
			out[k] = jsonValue(item)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = jsonValue(item)
		}
		return out
	case time.Time:
		return t.Format(time.RFC3339)
	default:
		return v
	}
}

func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	var e event
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&e); err != nil {
		http.Error(w, "invalid event", http.StatusBadRequest)
		return
	}
	body := e.Ack
	if body == nil {
		body = e.Checkin
	}
	if body == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	report := map[string]any{}
	if raw, err := base64.StdEncoding.DecodeString(body.RawPayload); err == nil && len(raw) > 0 {
		_, _ = plist.Unmarshal(raw, &report)
	}
	udid := body.UDID
	if udid == "" {
		udid = body.Enrollment
	}
	if udid == "" {
		udid, _ = report["UDID"].(string)
	}
	var err error
	switch e.Topic {
	case "mdm.Connect":
		uuid, status := body.CommandUUID, body.Status
		if uuid == "" {
			uuid, _ = report["CommandUUID"].(string)
		}
		if status == "" {
			status, _ = report["Status"].(string)
		}
		err = s.State.Answered(udid, uuid, status, guessType(report), jsonValue(report))
	case "mdm.Authenticate":
		serial, _ := report["SerialNumber"].(string)
		product, _ := report["ProductName"].(string)
		osVersion, _ := report["OSVersion"].(string)
		err = s.State.Authenticate(udid, serial, product, osVersion)
	case "mdm.TokenUpdate":
		token, _ := report["UnlockToken"].([]byte)
		var fresh bool
		if fresh, err = s.State.TokenUpdate(udid, token); err == nil && fresh {
			go s.afterEnrollment(udid)
		}
	case "mdm.CheckOut":
		err = s.State.CheckOut(udid)
	default:
		err = s.State.Event(udid, strings.TrimPrefix(e.Topic, "mdm."), nil)
	}
	if err != nil {
		s.Log.Error("webhook event not kept", "topic", e.Topic, "udid", udid, "err", err)
		http.Error(w, "state failed", http.StatusInternalServerError)
		return
	}
	// 200, not 204: the webhook of NanoMDM takes any other status for a failure and logs it
	w.WriteHeader(http.StatusOK)
}

// afterEnrollment: the device does not synchronize DDM by itself after an enrollment (checked), so the declarations
// of its sets come back with a notify; then ProfileList refreshes the "installed" marks of the UI
func (s *Server) afterEnrollment(udid string) {
	time.Sleep(s.RefreshDelay)
	if status, _, err := s.NanoHUB.NotifyDDM(udid); err != nil || status/100 != 2 {
		s.Log.Warn("DDM notify after the enrollment failed", "udid", udid, "status", status, "err", err)
	}
	time.Sleep(s.RefreshDelay)
	if _, err := s.send(udid, "ProfileList", nil); err != nil {
		s.Log.Warn("ProfileList after the enrollment failed", "udid", udid, "err", err)
	}
	s.Enrolled("ios", udid)
}
