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
	"os"
	"path/filepath"
	"strings"
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
	reg, err := OpenRegistry(filepath.Join(t.TempDir(), "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{CA: ca, Challenges: NewChallenges(time.Minute), Days: 30, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Registry: reg, Enrolled: func(string) bool { return false }}
	return s, httptest.NewServer(s)
}

// request is a PKCSReq of a fresh key, the way iOS makes it: a self-signed signer, the CSR with the challenge
func request(t *testing.T, ca *x509.Certificate, challenge string, signer *x509.Certificate, signerKey *rsa.PrivateKey, kind scep.MessageType) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	return requestAs(t, "device-1", ca, challenge, signer, signerKey, kind)
}

func requestAs(t *testing.T, cn string, ca *x509.Certificate, challenge string, signer *x509.Certificate, signerKey *rsa.PrivateKey, kind scep.MessageType) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}},
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
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
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
	// the subject is the one of the server, never the one of the CSR
	if crt == nil || !strings.HasPrefix(crt.Subject.CommonName, "mcloud-mdm-") || UDIDOfSubject(crt.Subject.CommonName) != "" ||
		!s.CA.Issued(crt) || crt.Subject.Organization[0] != "Test" {
		t.Fatalf("certificate: %+v", crt)
	}
	if id, ok := s.Registry.Get(SerialOf(crt)); !ok || id.Origin != OriginEnrollment || id.Subject != crt.Subject.CommonName {
		t.Errorf("the identity is not in the registry: %+v %v", id, ok)
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

func TestBoundChallenge(t *testing.T) {
	s, srv := newServer(t)
	defer srv.Close()
	const udid = "00008020-0005308201DA002E"
	// the identity of another device with the challenge of a profile for udid: refused, and the challenge is used
	challenge, err := s.Challenges.NewFor(udid)
	if err != nil {
		t.Fatal(err)
	}
	for _, cn := range []string{"device-1", SubjectPrefix("00008020-0005308201DA0000") + "1a2b3c4d", "mcloud-mdm-" + udid} {
		body, _, _ := requestAs(t, cn, s.CA.Cert, challenge, nil, nil, scep.PKCSReq)
		if reply := post(t, srv.URL, body); reply.PKIStatus != scep.FAILURE || reply.FailInfo != scep.BadRequest {
			t.Errorf("%s: %v %v", cn, reply.PKIStatus, reply.FailInfo)
		}
		challenge, _ = s.Challenges.NewFor(udid)
	}
	if s.Challenges.Pending() != 1 {
		t.Errorf("pending: %d", s.Challenges.Pending())
	}
	// the identity of the device of the profile: signed
	body, key, signer := requestAs(t, SubjectPrefix(udid)+"1a2b3c4d", s.CA.Cert, challenge, nil, nil, scep.PKCSReq)
	reply := post(t, srv.URL, body)
	if reply.PKIStatus != scep.SUCCESS {
		t.Fatalf("status %v fail %v", reply.PKIStatus, reply.FailInfo)
	}
	if err := reply.DecryptPKIEnvelope(signer, key); err != nil {
		t.Fatal(err)
	}
	if cn := reply.Certificate.Subject.CommonName; UDIDOfSubject(cn) != udid {
		t.Errorf("certificate: %q", cn)
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

// enroll signs an identity for the grant with a CSR of the common name cn: the certificate and its key
func enroll(t *testing.T, s *Server, url string, g Grant, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	challenge, err := s.Challenges.Issue(g)
	if err != nil {
		t.Fatal(err)
	}
	body, key, signer := requestAs(t, cn, s.CA.Cert, challenge, nil, nil, scep.PKCSReq)
	reply := post(t, url, body)
	if reply.PKIStatus != scep.SUCCESS {
		t.Fatalf("enroll: %v %v", reply.PKIStatus, reply.FailInfo)
	}
	if err := reply.DecryptPKIEnvelope(signer, key); err != nil {
		t.Fatal(err)
	}
	return reply.Certificate, key
}

// renew renews the identity: the new certificate and its key, or nil and the failure
func renew(t *testing.T, s *Server, url string, crt *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, scep.FailInfo) {
	t.Helper()
	body, _, _ := requestAs(t, "anything", s.CA.Cert, "", crt, key, scep.RenewalReq)
	reply := post(t, url, body)
	if reply.PKIStatus != scep.SUCCESS {
		return nil, nil, reply.FailInfo
	}
	if err := reply.DecryptPKIEnvelope(crt, key); err != nil {
		t.Fatal(err)
	}
	// the key of the CSR is a new one, requestAs keeps it: the renewed certificate is checked by its subject only
	return reply.Certificate, nil, ""
}

func TestForcedSubjectAndRegistry(t *testing.T) {
	s, srv := newServer(t)
	defer srv.Close()
	const udid = "00008020-0005308201DA002E"
	subject := SubjectPrefix(udid) + "1A2B3C4D"
	// the CSR asks for another subject: the one of the grant is signed
	first, key := enroll(t, s, srv.URL, Grant{Subject: subject, UDID: udid, Node: "node-a"}, "mcloud-mdm-00008020-0005308201DA0000-00000000")
	if first.Subject.CommonName != subject {
		t.Fatalf("subject %q", first.Subject.CommonName)
	}
	id, ok := s.Registry.Get(SerialOf(first))
	if !ok || id.UDID != udid || id.Node != "node-a" || id.Revoked() || id.Origin != OriginEnrollment {
		t.Fatalf("registry: %+v %v", id, ok)
	}
	// a renewal keeps the subject, the device and the node
	renewed, _, info := renew(t, s, srv.URL, first, key)
	if renewed == nil || renewed.Subject.CommonName != subject {
		t.Fatalf("renewal: %v %v", renewed, info)
	}
	child, _ := s.Registry.Get(SerialOf(renewed))
	if child.Origin != OriginRenewal || child.Parent != SerialOf(first) || child.UDID != udid || child.Node != "node-a" {
		t.Errorf("renewed: %+v", child)
	}
	// a second renewal by the same identity replaces the first renewed one: one lineage
	again, _, _ := renew(t, s, srv.URL, first, key)
	if again == nil {
		t.Fatal("a second renewal of the identity is refused")
	}
	if old, _ := s.Registry.Get(SerialOf(renewed)); !old.Revoked() || old.Reason != "replaced by a newer renewal" {
		t.Errorf("the replaced renewal: %+v", old)
	}
	// a new enrollment of the device revokes its identities
	second, _ := enroll(t, s, srv.URL, Grant{Subject: SubjectPrefix(udid) + "5E6F7A8B", UDID: udid}, "x")
	for _, c := range []*x509.Certificate{first, again} {
		if old, _ := s.Registry.Get(SerialOf(c)); !old.Revoked() || old.Reason != "replaced by a new enrollment" {
			t.Errorf("an identity of the enrolled device: %+v", old)
		}
	}
	if cur, _ := s.Registry.Get(SerialOf(second)); cur.Revoked() {
		t.Error("the new identity is revoked")
	}
	// a revoked identity does not renew
	if crt, _, info := renew(t, s, srv.URL, first, key); crt != nil || info != scep.BadMessageCheck {
		t.Errorf("a revoked identity renewed: %v %v", crt, info)
	}
	// an identity of the CA the registry does not know, signed after its start: refused
	other, otherKey := issueDirect(t, s.CA, SubjectPrefix("00008020-0005308201DA00FF")+"1A2B3C4D", time.Now())
	if crt, _, info := renew(t, s, srv.URL, other, otherKey); crt != nil || info != scep.BadMessageCheck {
		t.Errorf("an unknown identity renewed: %v %v", crt, info)
	}
}

// issueDirect signs an identity of the CA outside the SCEP server (an identity of before the registry): notBefore is
// its signature time
func issueDirect(t *testing.T, ca *CA, cn string, notBefore time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore.Add(-5 * time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(der)
	return crt, key
}

func TestAdoptionOfIdentitiesBeforeTheRegistry(t *testing.T) {
	s, srv := newServer(t)
	defer srv.Close()
	const udid, other = "00008020-0005308201DA002E", "00008020-0005308201DA00FF"
	enrolled := map[string]bool{udid: true}
	s.Enrolled = func(u string) bool { return enrolled[u] }
	before := s.Registry.Since().Add(-48 * time.Hour)
	// of a device that is not enrolled, without a udid in its subject: refused
	notEnrolled, k1 := issueDirect(t, s.CA, SubjectPrefix(other)+"1A2B3C4D", before)
	noUDID, k2 := issueDirect(t, s.CA, "mcloud-mdm-1A2B3C4D", before)
	for name, c := range map[*x509.Certificate]*rsa.PrivateKey{notEnrolled: k1, noUDID: k2} {
		if crt, _, info := renew(t, s, srv.URL, name, c); crt != nil || info != scep.BadMessageCheck {
			t.Errorf("%s adopted: %v", name.Subject.CommonName, info)
		}
	}
	// of an enrolled device: adopted at its first renewal
	old, key := issueDirect(t, s.CA, SubjectPrefix(udid)+"1A2B3C4D", before)
	renewed, _, info := renew(t, s, srv.URL, old, key)
	if renewed == nil || renewed.Subject.CommonName != old.Subject.CommonName {
		t.Fatalf("the identity of an enrolled device is not adopted: %v", info)
	}
	if id, _ := s.Registry.Get(SerialOf(old)); id.Origin != OriginAdopted || id.UDID != udid {
		t.Errorf("adopted: %+v", id)
	}
	if id, _ := s.Registry.Get(SerialOf(renewed)); id.Origin != OriginRenewal || id.Parent != SerialOf(old) {
		t.Errorf("renewed: %+v", id)
	}
	// another identity of before the registry of the same device: it has a newer one
	twin, twinKey := issueDirect(t, s.CA, SubjectPrefix(udid)+"5E6F7A8B", before)
	if crt, _, info := renew(t, s, srv.URL, twin, twinKey); crt != nil || info != scep.BadMessageCheck {
		t.Errorf("a second identity of before the registry adopted: %v", info)
	}
}

func TestRegistryPersistsAndRevokesNodes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identities.json")
	reg, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := LoadOrCreateCA(filepath.Join(dir, "scep"), "Test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	add := func(cn, udid, node, parent string, issued time.Time) *x509.Certificate {
		c, _ := issueDirect(t, ca, cn, issued)
		if err := reg.Record(c, Identity{UDID: udid, Node: node, Parent: parent, Origin: OriginEnrollment,
			IssuedAt: issued.UTC().Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	a1 := add(SubjectPrefix("00008020-000000000000000A")+"00000001", "00008020-000000000000000A", "node-a", "", now.Add(-2*time.Hour))
	// renewed after the revocation of its node: of a profile of before it
	a2 := add(SubjectPrefix("00008020-000000000000000A")+"00000002", "00008020-000000000000000A", "node-a", SerialOf(a1), now)
	// a profile of node-a after its revocation (enrolled again under the same label)
	a3 := add(SubjectPrefix("00008020-000000000000000B")+"00000003", "00008020-000000000000000B", "node-a", "", now)
	b := add(SubjectPrefix("00008020-000000000000000C")+"00000004", "00008020-000000000000000C", "node-b", "", now)
	c := add(SubjectPrefix("00008020-000000000000000D")+"00000005", "00008020-000000000000000D", "node-c", "", now)
	// an empty list of STF revokes nothing
	if out, err := reg.RevokeNodes(nil); err != nil || len(out) != 0 {
		t.Fatalf("an empty list: %v %v", out, err)
	}
	out, err := reg.RevokeNodes([]NodeStatus{{Label: "node-a", Revoked: true, RevokedAt: now.Add(-time.Hour)},
		{Label: "node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, id := range out {
		got[id.Serial] = id.Reason
	}
	want := map[string]string{SerialOf(a1): "node revoked", SerialOf(a2): "node revoked", SerialOf(c): "node deleted"}
	if len(got) != len(want) {
		t.Errorf("revoked: %v", got)
	}
	for serial, reason := range want {
		if got[serial] != reason {
			t.Errorf("%s: %q, want %q", serial, got[serial], reason)
		}
	}
	// the file: mode 600, the same start and identities after a restart
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v %v", info, err)
	}
	again, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Since().Equal(reg.Since()) || len(again.List()) != 5 {
		t.Errorf("reopened: %v %d", again.Since(), len(again.List()))
	}
	for _, crt := range []*x509.Certificate{a3, b} {
		if id, _ := again.Get(SerialOf(crt)); id.Revoked() {
			t.Errorf("revoked: %+v", id)
		}
	}
	if nodes := again.Nodes(); strings.Join(nodes, ",") != "node-a,node-b" {
		t.Errorf("nodes: %v", nodes)
	}
}

func TestUDIDOfSubject(t *testing.T) {
	for cn, want := range map[string]string{
		"mcloud-mdm-00008020-0005308201DA002E-1A2B3C4D":                "00008020-0005308201DA002E",
		"mcloud-mdm-0123456789abcdef0123456789abcdef01234567-1A2B3C4D": "0123456789abcdef0123456789abcdef01234567",
		"mcloud-mdm-1A2B3C4D": "", "device-1": "", "mcloud-mdm-00008020-0005308201DA002E-1A2B3C4": "",
	} {
		if got := UDIDOfSubject(cn); got != want {
			t.Errorf("%s: %q", cn, got)
		}
	}
}
