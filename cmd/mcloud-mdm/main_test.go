package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/scep"
	"github.com/zebrunner/mcloud-mdm/internal/stf"
)

func TestBanner(t *testing.T) {
	if got, want := banner("mcloud-mdm", "1.2.3"), "\u2501\u2501 mcloud-mdm 1.2.3"; got != want {
		t.Errorf("banner without facts = %q, want %q", got, want)
	}
	if got, want := banner("mcloud-mdm", "1.2.3", "a", "b c"), "\u2501\u2501 mcloud-mdm 1.2.3 \u00b7 a \u00b7 b c"; got != want {
		t.Errorf("banner with facts = %q, want %q", got, want)
	}
}

func TestSyncNodes(t *testing.T) {
	dir := t.TempDir()
	reg, err := scep.OpenRegistry(filepath.Join(dir, "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := scep.LoadOrCreateCA(filepath.Join(dir, "scep"), "Org")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	crt, err := ca.Issue(csr, scep.SubjectPrefix("00008020-0005308201DA002E")+"1A2B3C4D", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Record(crt, scep.Identity{UDID: "00008020-0005308201DA002E", Node: "node-a", Origin: scep.OriginEnrollment}); err != nil {
		t.Fatal(err)
	}
	// STF refuses first (a token that is not of an admin), then node-a is revoked
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"nodes":[{"label":"node-a","status":"revoked","revokedAt":"` +
			time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"}]}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncNodes(ctx, stf.New(srv.URL, "token"), reg, slog.New(slog.NewTextHandler(io.Discard, nil)), 10*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if id, _ := reg.Get(scep.SerialOf(crt)); id.Revoked() {
			if id.Reason != "node revoked" || calls.Load() < 2 {
				t.Errorf("revoked: %+v after %d calls", id, calls.Load())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the identity of the revoked node is not revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
