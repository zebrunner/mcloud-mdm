// Package config reads the configuration of mcloud-mdm from the environment (README.md#configuration).
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the validated configuration.
type Config struct {
	// PublicURL is the base the devices and the agents reach: <PublicURL>/mdm, <PublicURL>/mdm/enroll
	PublicURL string
	// SCEPURL is the SCEP endpoint written into the enrollment profile, <PublicURL>/scep by default
	SCEPURL string
	// DeviceListen serves the devices and the agents: /mdm/enroll, /scep, /healthz (published by the proxy)
	DeviceListen string
	// AdminListen serves the UI, its API and the webhook of NanoHUB (never published outside of the host)
	AdminListen string
	DataDir     string
	NanoHUBURL  string
	NanoHUBKey  string
	// EnrollToken authorizes GET /mdm/enroll (the agents of the device hosts)
	EnrollToken string
	// ProfileID is the PayloadIdentifier of the enrollment profile
	ProfileID string
	OrgName   string
	// TLSCAFile is the PEM CA of a self-signed MDM server: the profile installs it and pins the MDM server to it
	TLSCAFile    string
	ChallengeTTL time.Duration
	CertDays     int
	LogLevel     slog.Level
}

// Load reads the environment; every invalid variable is reported in the returned error.
func Load(getenv func(string) string) (*Config, error) {
	get := func(name, def string) string {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	c := &Config{
		PublicURL:    strings.TrimRight(get("MDM_PUBLIC_URL", ""), "/"),
		SCEPURL:      get("MDM_SCEP_URL", ""),
		DeviceListen: get("MDM_DEVICE_LISTEN", ":8080"),
		AdminListen:  get("MDM_ADMIN_LISTEN", ":8081"),
		DataDir:      get("MDM_DATA_DIR", "/data"),
		NanoHUBURL:   strings.TrimRight(get("NANOHUB_URL", "http://mdm-nanohub:9004"), "/"),
		NanoHUBKey:   get("NANOHUB_API_KEY", ""),
		EnrollToken:  get("MDM_ENROLL_TOKEN", ""),
		ProfileID:    get("MDM_PROFILE_ID", "com.zebrunner.mcloud.mdm"),
		OrgName:      get("MDM_ORG_NAME", "Zebrunner MCloud"),
		TLSCAFile:    get("MDM_TLS_CA_FILE", ""),
	}
	if u, err := url.Parse(c.PublicURL); c.PublicURL == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, fmt.Errorf("MDM_PUBLIC_URL %q: the https URL the devices reach, e.g. https://mcloud.example.com", c.PublicURL))
	}
	if c.SCEPURL == "" {
		c.SCEPURL = c.PublicURL + "/scep"
	} else if u, err := url.Parse(c.SCEPURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		errs = append(errs, fmt.Errorf("MDM_SCEP_URL %q: an http(s) URL", c.SCEPURL))
	}
	if c.NanoHUBKey == "" {
		errs = append(errs, errors.New("NANOHUB_API_KEY is empty: the API key of NanoHUB"))
	}
	if len(c.EnrollToken) < 16 {
		errs = append(errs, errors.New("MDM_ENROLL_TOKEN: a secret of 16+ characters the agents enroll the devices with"))
	}
	if c.TLSCAFile != "" {
		if _, err := os.Stat(c.TLSCAFile); err != nil {
			errs = append(errs, fmt.Errorf("MDM_TLS_CA_FILE: %w", err))
		}
	}
	ttl, err := time.ParseDuration(get("MDM_CHALLENGE_TTL", "10m"))
	if err != nil || ttl <= 0 {
		errs = append(errs, fmt.Errorf("MDM_CHALLENGE_TTL %q: a duration, e.g. 10m", getenv("MDM_CHALLENGE_TTL")))
	}
	c.ChallengeTTL = ttl
	days, err := strconv.Atoi(get("MDM_CERT_DAYS", "365"))
	if err != nil || days < 1 || days > 3650 {
		errs = append(errs, fmt.Errorf("MDM_CERT_DAYS %q: the validity of the device identities, 1-3650 days", getenv("MDM_CERT_DAYS")))
	}
	c.CertDays = days
	if err := c.LogLevel.UnmarshalText([]byte(get("LOGGER_LEVEL", "INFO"))); err != nil {
		errs = append(errs, fmt.Errorf("LOGGER_LEVEL %q: DEBUG, INFO, WARN or ERROR", getenv("LOGGER_LEVEL")))
	}
	return c, errors.Join(errs...)
}
