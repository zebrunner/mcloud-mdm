package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/zebrunner/mcloud-mdm/internal/scep"
)

func TestIdentities(t *testing.T) {
	_, srv, _, s := setupServer(t)
	dir := t.TempDir()
	reg, err := scep.OpenRegistry(filepath.Join(dir, "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := scep.LoadOrCreateCA(filepath.Join(dir, "scep"), "Org")
	if err != nil {
		t.Fatal(err)
	}
	s.Identities = reg
	issue := func(udid, node string) *x509.Certificate {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		csr, _ := x509.ParseCertificateRequest(der)
		crt, err := ca.Issue(csr, scep.SubjectPrefix(udid)+"1A2B3C4D", 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Record(crt, scep.Identity{UDID: udid, Node: node, Origin: scep.OriginEnrollment}); err != nil {
			t.Fatal(err)
		}
		return crt
	}
	a := issue(udid, "node-a")
	b := issue("00008020-0005308201DA00FF", "node-b")
	resp, err := http.Get(srv.URL + "/api/identities")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Since      string          `json:"since"`
		Identities []scep.Identity `json:"identities"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(list.Identities) != 2 || list.Since == "" {
		t.Fatalf("list: %d %+v", resp.StatusCode, list)
	}
	for _, body := range []map[string]any{{}, {"serial": "XYZ"}, {"udid": udid, "node": "node-a"}, {"node": "Node A"}} {
		if code, _ := postJSON(t, srv.URL+"/api/identities/revoke", body); code != http.StatusBadRequest {
			t.Errorf("%v: %d", body, code)
		}
	}
	code, out := postJSON(t, srv.URL+"/api/identities/revoke", map[string]any{"node": "node-a"})
	if revoked, _ := out["revoked"].([]any); code != http.StatusOK || len(revoked) != 1 {
		t.Errorf("revoke node-a: %d %v", code, out)
	}
	if id, _ := reg.Get(scep.SerialOf(a)); !id.Revoked() || id.Reason != "revoked by an admin" {
		t.Errorf("a: %+v", id)
	}
	code, out = postJSON(t, srv.URL+"/api/identities/revoke", map[string]any{"serial": scep.SerialOf(b)})
	if revoked, _ := out["revoked"].([]any); code != http.StatusOK || len(revoked) != 1 {
		t.Errorf("revoke the serial of b: %d %v", code, out)
	}
	code, out = postJSON(t, srv.URL+"/api/identities/revoke", map[string]any{"udid": udid})
	if revoked, _ := out["revoked"].([]any); code != http.StatusOK || len(revoked) != 0 {
		t.Errorf("revoke again: %d %v", code, out)
	}
}
