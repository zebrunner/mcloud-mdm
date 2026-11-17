package scep

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strings"

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
	switch msg.MessageType {
	case scep.PKCSReq:
		if !s.Challenges.Consume(msg.ChallengePassword) {
			return fail("the challenge is unknown, used or expired", scep.BadRequest)
		}
	case scep.RenewalReq:
		if !s.CA.Issued(msg.SignerCert) {
			return fail("the renewal is not signed by a valid identity of the CA", scep.BadMessageCheck)
		}
	default:
		return fail("unsupported message type", scep.BadRequest)
	}
	if err := msg.CSR.CheckSignature(); err != nil {
		return fail("the CSR signature is invalid", scep.BadMessageCheck)
	}
	crt, err := s.CA.Issue(msg.CSR, s.Days)
	if err != nil {
		return nil, err
	}
	s.Log.Info("device identity issued", "subject", crt.Subject.String(), "type", string(msg.MessageType), "until", crt.NotAfter)
	return msg.Success(s.CA.Cert, s.CA.Key, crt)
}
