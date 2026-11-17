// Package scep is the SCEP server of the device identities: the enrollment profile asks the device for a certificate
// with a one-time challenge, NanoHUB trusts the CA of these certificates (its -ca).
package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA is the certificate authority of the device identities.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// LoadOrCreateCA reads ca.pem and ca.key of dir (the format of micromdm/scep too: an existing depot keeps the
// identities it issued valid) or creates them.
func LoadOrCreateCA(dir, org string) (*CA, bool, error) {
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if _, err := os.Stat(certPath); err == nil {
		ca, err := loadCA(certPath, keyPath)
		return ca, false, err
	}
	// readable: NanoHUB reads ca.pem of a shared volume; the key itself is 600
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: org + " SCEP CA", Organization: []string{org}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, false, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		return nil, false, err
	}
	// world readable: NanoHUB mounts the certificate as its -ca
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, false, err
	}
	return &CA{Cert: cert, Key: key}, true, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM key", keyPath)
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k8, err8 := x509.ParsePKCS8PrivateKey(block.Bytes); err8 == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA key", keyPath)
		}
		key = rk
	} else {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("the SCEP CA key does not match its certificate")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Issue signs a client certificate of the device for the public key and the subject of the CSR.
func (ca *CA) Issue(csr *x509.CertificateRequest, days int) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Issued reports whether cert is a valid identity of this CA (the renewal of a device signs with it).
func (ca *CA) Issued(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err == nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
