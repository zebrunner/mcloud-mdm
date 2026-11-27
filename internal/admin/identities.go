package admin

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/scep"
)

// the forms of the selectors of a revocation
var (
	serialForm = regexp.MustCompile(`^[0-9a-f]{1,40}$`)
	udidForm   = regexp.MustCompile(`^[0-9A-Fa-f-]{20,64}$`)
	nodeForm   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// identities lists the device identities of the SCEP CA, the newest first, with the start of the registry
func (s *Server) identities(w http.ResponseWriter, _ *http.Request) {
	if s.Identities == nil {
		fail(w, http.StatusNotFound, errors.New("no registry of the identities"))
		return
	}
	reply(w, http.StatusOK, map[string]any{"since": s.Identities.Since().Format(time.RFC3339),
		"identities": s.Identities.List()})
}

// identitiesRevoke revokes the identities of a serial, a udid or a node ({"serial"|"udid"|"node": ...}): they renew
// no more
func (s *Server) identitiesRevoke(w http.ResponseWriter, _ *http.Request, body map[string]any) {
	if s.Identities == nil {
		fail(w, http.StatusNotFound, errors.New("no registry of the identities"))
		return
	}
	serial, udid, node := str(body, "serial"), str(body, "udid"), str(body, "node")
	var revoked []scep.Identity
	var err error
	switch {
	case serial != "" && udid == "" && node == "" && serialForm.MatchString(serial):
		var ok bool
		if ok, err = s.Identities.RevokeSerial(serial, "revoked by an admin"); ok {
			id, _ := s.Identities.Get(serial)
			revoked = append(revoked, id)
		}
	case udid != "" && serial == "" && node == "" && udidForm.MatchString(udid):
		revoked, err = s.Identities.RevokeUDID(udid, "revoked by an admin", "")
	case node != "" && serial == "" && udid == "" && nodeForm.MatchString(node):
		revoked, err = s.Identities.RevokeNode(node, "revoked by an admin", time.Time{})
	default:
		fail(w, http.StatusBadRequest, errors.New("one of serial (lower case hex), udid or node"))
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	for _, id := range revoked {
		s.Log.Info("device identity revoked", "serial", id.Serial, "udid", id.UDID, "node", id.Node, "reason", id.Reason)
	}
	if revoked == nil {
		revoked = []scep.Identity{}
	}
	reply(w, http.StatusOK, map[string]any{"revoked": revoked})
}
