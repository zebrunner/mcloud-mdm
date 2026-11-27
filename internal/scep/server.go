package scep

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

// caps are the capabilities of GetCACaps: iOS signs with SHA-256 and encrypts with AES when they are listed
const caps = "Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation"

// maxMessage limits a PKIOperation request: a CSR in a PKCS#7 envelope is a few kilobytes
const maxMessage = 64 << 10

// Server answers GetCACaps, GetCACert and PKIOperation (RFC 8894) on its path.
type Server struct {
	CA         *CA
	Challenges *Challenges
	Days       int
	Log        *slog.Logger
	// Registry keeps the signed identities: a renewal is signed for a known identity that is not revoked only
	Registry *Registry
	// Enrolled reports whether the device of the udid is enrolled (the webhook of NanoHUB): an identity signed before
	// the registry is adopted at its first renewal only for an enrolled device (adopt)
	Enrolled func(udid string) bool
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch op := r.URL.Query().Get("operation"); op {
	case "GetCACaps":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, caps)
	case "GetCACert":
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		_, _ = w.Write(s.CA.Cert.Raw)
	case "PKIOperation":
		s.pkiOperation(w, r)
	default:
		http.Error(w, "unknown SCEP operation", http.StatusBadRequest)
	}
}

func (s *Server) pkiOperation(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var err error
	switch r.Method {
	case http.MethodPost:
		data, err = io.ReadAll(io.LimitReader(r.Body, maxMessage))
	case http.MethodGet:
		// the base64 of a GET may come with spaces for the "+" of a query not escaped by the client
		msg := strings.ReplaceAll(r.URL.Query().Get("message"), " ", "+")
		data, err = base64.StdEncoding.DecodeString(msg)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(data) == 0 {
		http.Error(w, "no SCEP message", http.StatusBadRequest)
		return
	}
	msg, err := scep.ParsePKIMessage(data)
	if err != nil {
		s.Log.Warn("SCEP message is invalid", "err", err)
		http.Error(w, "invalid SCEP message", http.StatusBadRequest)
		return
	}
	// ParsePKIMessage verified the signature but keeps the signer to itself: the renewal is authorized by it
	if p7, err := pkcs7.Parse(data); err == nil {
		msg.SignerCert = p7.GetOnlySigner()
	}
	if err := msg.DecryptPKIEnvelope(s.CA.Cert, s.CA.Key); err != nil {
		s.Log.Warn("SCEP envelope does not decrypt with the CA", "err", err)
		http.Error(w, "invalid SCEP envelope", http.StatusBadRequest)
		return
	}
	reply, err := s.answer(msg)
	if err != nil {
		s.Log.Error("SCEP reply failed", "err", err)
		http.Error(w, "SCEP reply failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pki-message")
	_, _ = w.Write(reply.Raw)
}

// answer signs the CSR of a valid one-time challenge or of a renewal signed by an identity of the CA, and refuses
// the others with a CertRep of failure (the device shows the error of its profile).
func (s *Server) answer(msg *scep.PKIMessage) (*scep.PKIMessage, error) {
	fail := func(reason string, info scep.FailInfo) (*scep.PKIMessage, error) {
		s.Log.Warn("SCEP request refused", "reason", reason, "type", string(msg.MessageType), "transaction", string(msg.TransactionID))
		return msg.Fail(s.CA.Cert, s.CA.Key, info)
	}
	if msg.CSRReqMessage == nil || msg.CSR == nil {
		return fail("no CSR", scep.BadRequest)
	}
	var grant Grant
	var parent *Identity
	switch msg.MessageType {
	case scep.PKCSReq:
		g, ok := s.Challenges.Take(msg.ChallengePassword)
		if !ok {
			return fail("the challenge is unknown, used or expired", scep.BadRequest)
		}
		// a challenge of a profile for one device (the binding of the nodes) signs the identity of that device only
		if g.Bound && g.UDID != "" && !strings.HasPrefix(msg.CSR.Subject.CommonName, SubjectPrefix(g.UDID)) {
			return fail("the CSR is not of the device of the challenge "+g.UDID, scep.BadRequest)
		}
		grant = g
	case scep.RenewalReq:
		if !s.CA.Issued(msg.SignerCert) {
			return fail("the renewal is not signed by a valid identity of the CA", scep.BadMessageCheck)
		}
		id, reason := s.renewable(msg.SignerCert)
		if id == nil {
			return fail("the renewal of the identity "+SerialOf(msg.SignerCert)+": "+reason, scep.BadMessageCheck)
		}
		parent = id
		// the identity keeps its subject, its device and its node
		grant = Grant{Subject: id.Subject, UDID: id.UDID, Node: id.Node}
	default:
		return fail("unsupported message type", scep.BadRequest)
	}
	if err := msg.CSR.CheckSignature(); err != nil {
		return fail("the CSR signature is invalid", scep.BadMessageCheck)
	}
	subject := grant.Subject
	if subject == "" {
		subject = "mcloud-mdm-" + randomHex8()
		if grant.UDID != "" {
			subject = SubjectPrefix(grant.UDID) + randomHex8()
		}
	}
	crt, err := s.CA.Issue(msg.CSR, subject, s.Days)
	if err != nil {
		return nil, err
	}
	if err := s.record(crt, grant, parent); err != nil {
		// an identity the registry does not know would not renew: none is given
		return nil, fmt.Errorf("the registry of the identities: %w", err)
	}
	s.Log.Info("device identity issued", "subject", crt.Subject.String(), "serial", SerialOf(crt), "udid", grant.UDID,
		"node", grant.Node, "type", string(msg.MessageType), "until", crt.NotAfter)
	return msg.Success(s.CA.Cert, s.CA.Key, crt)
}

func randomHex8() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

// renewable returns the identity of the registry a renewal signed by cert renews, or nil and the reason of the refusal
func (s *Server) renewable(cert *x509.Certificate) (*Identity, string) {
	if s.Registry == nil {
		return &Identity{Serial: SerialOf(cert), Subject: cert.Subject.CommonName, UDID: UDIDOfSubject(cert.Subject.CommonName)}, ""
	}
	id, known := s.Registry.Get(SerialOf(cert))
	switch {
	case known && id.Revoked():
		return nil, "revoked (" + id.Reason + ")"
	case known:
		return &id, ""
	}
	return s.adopt(cert)
}

// adopt takes an identity signed before the registry into it at its first renewal, the safest rule that keeps the
// devices enrolled before it: the certificate verifies (the caller checked it), was signed before the start of the
// registry (every later one is in it), its common name names a udid (mcloud-mdm-<udid>-...) of a device enrolled now
// and the device has no identity of the registry yet (a newer enrollment replaced the old ones). Anything else is
// refused: the device enrolls again.
func (s *Server) adopt(cert *x509.Certificate) (*Identity, string) {
	since := s.Registry.Since()
	// Issue backdates NotBefore by 5 minutes
	if !cert.NotBefore.Add(5 * time.Minute).Before(since) {
		return nil, "unknown, signed after the start of the registry"
	}
	udid := UDIDOfSubject(cert.Subject.CommonName)
	if udid == "" {
		return nil, "unknown, its subject names no device"
	}
	if s.Enrolled == nil || !s.Enrolled(udid) {
		return nil, "unknown, its device " + udid + " is not enrolled"
	}
	if s.Registry.Active(udid) {
		return nil, "unknown, the device " + udid + " has a newer identity"
	}
	id := Identity{UDID: udid, Origin: OriginAdopted, IssuedAt: cert.NotBefore.UTC().Format(time.RFC3339)}
	if err := s.Registry.Record(cert, id); err != nil {
		return nil, "unknown, not adopted: " + err.Error()
	}
	s.Log.Warn("device identity signed before the registry adopted at its renewal", "serial", SerialOf(cert),
		"subject", cert.Subject.CommonName, "udid", udid)
	adopted, _ := s.Registry.Get(SerialOf(cert))
	return &adopted, ""
}

// record keeps the new identity: an enrollment replaces the identities of its device, a renewal the identities
// renewed from the same one before (one lineage per device)
func (s *Server) record(crt *x509.Certificate, g Grant, parent *Identity) error {
	if s.Registry == nil {
		return nil
	}
	id := Identity{UDID: g.UDID, Node: g.Node, Origin: OriginEnrollment}
	if parent != nil {
		id.Origin, id.Parent = OriginRenewal, parent.Serial
	}
	if err := s.Registry.Record(crt, id); err != nil {
		return err
	}
	serial := SerialOf(crt)
	var revoked []Identity
	var err error
	if parent == nil {
		revoked, err = s.Registry.RevokeUDID(g.UDID, "replaced by a new enrollment", serial)
	} else {
		revoked, err = s.Registry.RevokeChildren(parent.Serial, "replaced by a newer renewal", serial)
	}
	for _, r := range revoked {
		s.Log.Info("device identity revoked", "serial", r.Serial, "udid", r.UDID, "reason", r.Reason)
	}
	return err
}
