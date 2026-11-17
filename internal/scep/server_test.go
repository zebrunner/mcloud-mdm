package scep

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

func newServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	ca, created, err := LoadOrCreateCA(t.TempDir(), "Test")
	if err != nil || !created {
		t.Fatalf("CA: %v %v", created, err)
	}
	s := &Server{CA: ca, Challenges: NewChallenges(time.Minute), Days: 30, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return s, httptest.NewServer(s)
}

// request is a PKCSReq of a fresh key, the way iOS makes it: a self-signed signer, the CSR with the challenge
func request(t *testing.T, ca *x509.Certificate, challenge string, signer *x509.Certificate, signerKey *rsa.PrivateKey, kind scep.MessageType) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-1"}},
		ChallengePassword:  challenge,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device-1"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		selfDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		signer, _ = x509.ParseCertificate(selfDER)
		signerKey = key
	}
	msg, err := scep.NewCSRRequest(csr, &scep.PKIMessage{MessageType: kind, Recipients: []*x509.Certificate{ca},
		SignerKey: signerKey, SignerCert: signer})
	if err != nil {
		t.Fatal(err)
	}
	return msg.Raw, signerKey, signer
}

func post(t *testing.T, url string, body []byte) *scep.PKIMessage {
	t.Helper()
	resp, err := http.Post(url+"?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, data)
	}
	reply, err := scep.ParsePKIMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestCapsAndCACert(t *testing.T) {
	s, srv := newServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("POSTPKIOperation")) || !bytes.Contains(body, []byte("SHA-256")) {
		t.Errorf("caps: %q", body)
	}
	resp, err = http.Get(srv.URL + "?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(body, s.CA.Cert.Raw) {
		t.Error("GetCACert is not the DER of the CA")
	}
}

func TestOneTimeChallenge(t *testing.T) {
	s, srv := newServer(t)
	defer srv.Close()
	challenge, err := s.Challenges.New()
	if err != nil {
		t.Fatal(err)
	}
	body, key, signer := request(t, s.CA.Cert, challenge, nil, nil, scep.PKCSReq)
	reply := post(t, srv.URL, body)
	if reply.PKIStatus != scep.SUCCESS {
		t.Fatalf("status %v fail %v", reply.PKIStatus, reply.FailInfo)
	}
	if err := reply.DecryptPKIEnvelope(signer, key); err != nil {
		t.Fatal(err)
	}
	crt := reply.Certificate
	if crt == nil || crt.Subject.CommonName != "device-1" || !s.CA.Issued(crt) {
		t.Fatalf("certificate: %+v", crt)
	}
	if s.Challenges.Pending() != 0 {
		t.Error("the challenge is still pending")
	}
	// the same challenge again: refused
	body, _, _ = request(t, s.CA.Cert, challenge, nil, nil, scep.PKCSReq)
	if reply := post(t, srv.URL, body); reply.PKIStatus != scep.FAILURE {
		t.Errorf("a used challenge signed again: %v", reply.PKIStatus)
	}
	// the renewal signed by the issued identity: signed without a challenge
	body, _, _ = request(t, s.CA.Cert, "", crt, key, scep.RenewalReq)
	if reply := post(t, srv.URL, body); reply.PKIStatus != scep.SUCCESS {
		t.Errorf("renewal: %v %v", reply.PKIStatus, reply.FailInfo)
	}
	// a renewal signed by a self-signed certificate: refused
	body, _, _ = request(t, s.CA.Cert, "", nil, nil, scep.RenewalReq)
	if reply := post(t, srv.URL, body); reply.PKIStatus != scep.FAILURE {
		t.Errorf("a self-signed renewal signed: %v", reply.PKIStatus)
	}
}

func TestUnknownChallenge(t *testing.T) {
	s, srv := newServer(t)
	defer srv.Close()
	body, _, _ := request(t, s.CA.Cert, "guess", nil, nil, scep.PKCSReq)
	if reply := post(t, srv.URL, body); reply.PKIStatus != scep.FAILURE || reply.FailInfo != scep.BadRequest {
		t.Errorf("unknown challenge: %v %v", reply.PKIStatus, reply.FailInfo)
	}
}

func TestChallengeExpires(t *testing.T) {
	c := NewChallenges(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	challenge, _ := c.New()
	now = now.Add(2 * time.Minute)
	if c.Consume(challenge) {
		t.Error("an expired challenge was accepted")
	}
	if c.Consume("") {
		t.Error("the empty challenge was accepted")
	}
}

func TestReloadCA(t *testing.T) {
	dir := t.TempDir()
	first, _, err := LoadOrCreateCA(dir, "Test")
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := LoadOrCreateCA(dir, "Test")
	if err != nil || created || !second.Cert.Equal(first.Cert) {
		t.Fatalf("reload: created=%v err=%v", created, err)
	}
}
