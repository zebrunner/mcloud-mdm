package config

import (
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func valid() map[string]string {
	return map[string]string{
		"MDM_PUBLIC_URL":   "https://mcloud.example.com/",
		"NANOHUB_API_KEY":  "key",
		"MDM_ENROLL_TOKEN": "0123456789abcdef",
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://mcloud.example.com" || c.SCEPURL != "https://mcloud.example.com/scep" {
		t.Errorf("urls: %q %q", c.PublicURL, c.SCEPURL)
	}
	if c.DeviceListen != ":8080" || c.AdminListen != ":8081" || c.ChallengeTTL != 10*time.Minute || c.CertDays != 365 {
		t.Errorf("defaults: %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	values := map[string]string{
		"MDM_PUBLIC_URL":    "http://plain",
		"MDM_SCEP_URL":      "ftp://x",
		"MDM_ENROLL_TOKEN":  "short",
		"MDM_CHALLENGE_TTL": "soon",
		"MDM_CERT_DAYS":     "0",
		"LOGGER_LEVEL":      "LOUD",
		"MDM_TLS_CA_FILE":   "/nonexistent/ca.pem",
	}
	_, err := Load(env(values))
	if err == nil {
		t.Fatal("no error")
	}
	for _, name := range []string{"MDM_PUBLIC_URL", "MDM_SCEP_URL", "NANOHUB_API_KEY", "MDM_ENROLL_TOKEN",
		"MDM_CHALLENGE_TTL", "MDM_CERT_DAYS", "LOGGER_LEVEL", "MDM_TLS_CA_FILE"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s is not reported: %v", name, err)
		}
	}
}

func TestSCEPOverride(t *testing.T) {
	values := valid()
	values["MDM_SCEP_URL"] = "http://10.0.0.1:8090/scep"
	c, err := Load(env(values))
	if err != nil || c.SCEPURL != "http://10.0.0.1:8090/scep" {
		t.Fatalf("%v %q", err, c.SCEPURL)
	}
}
