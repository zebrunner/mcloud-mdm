// Package config reads the configuration of mcloud-mdm from the environment (README.md#configuration).
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
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
	// AdminToken is required by every request of the admin listener: Authorization: Bearer <token> or the password of
	// Basic (any user), so a container of the same docker network cannot send MDM commands
	AdminToken string
	DataDir    string
	NanoHUBURL string
	NanoHUBKey string
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
	// HeadwindURL is the API of Headwind MDM, the server of the Android agents; empty: no Android
	HeadwindURL      string
	HeadwindLogin    string
	HeadwindPassword string
	// HeadwindPublicURL is the URL of Headwind MDM the agents reach, <PublicURL>/hmdm by default (the proxy of the
	// farm publishes it under a path of its domain: no DNS name or certificate of its own), HeadwindSecret its SHARED_SECRET
	HeadwindPublicURL string
	HeadwindSecret    string
	// HeadwindMQTTPort is the MQTT port of the agents: TLS on the host of HeadwindPublicURL when it is https
	HeadwindMQTTPort int
	// HeadwindTLSCAFile is the PEM CA of a private certificate of HeadwindPublicURL: the agents install it (a lab)
	HeadwindTLSCAFile string
	// HeadwindTLSPins are the TLS pins of HeadwindPublicURL for the agents (base64 of the SHA-256 of the
	// SubjectPublicKeyInfo of the certificate, comma separated, 4 at most); empty: none
	HeadwindTLSPins string
	// AgentAPK is the Android agent (make agent) served at /android/agent.apk
	AgentAPK string
	// AndroidLegacySetup: the nodes get the setup and the release commands with the shared secret in their arguments
	// (the agents without the staged form); false: the staged form only (the secret on stdin, no command line)
	AndroidLegacySetup bool
	// STFURL is the API of STF (MCloud) with an access token STFToken: the names, nodes and locations of the devices
	// and whether a user has one; empty: no groups and no jobs waiting for free devices
	STFURL   string
	STFToken string
	// EnforceNodeBinding: the node calls (/mdm/enroll, /android/release, ...) act only on the devices STF binds to the
	// node the proxy names (X-MCloud-Node); it needs STFURL
	EnforceNodeBinding bool
}

var headwindPath = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)?$`)

// tlsPin: the base64 of a SHA-256
var tlsPin = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

func validPins(pins string) bool {
	list := strings.Split(pins, ",")
	if len(list) > 4 {
		return false
	}
	for _, p := range list {
		if !tlsPin.MatchString(p) {
			return false
		}
	}
	return true
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
		AdminToken:   get("MDM_ADMIN_TOKEN", ""),
		DataDir:      get("MDM_DATA_DIR", "/data"),
		NanoHUBURL:   strings.TrimRight(get("NANOHUB_URL", "http://mdm-nanohub:9004"), "/"),
		NanoHUBKey:   get("NANOHUB_API_KEY", ""),
		EnrollToken:  get("MDM_ENROLL_TOKEN", ""),
		ProfileID:    get("MDM_PROFILE_ID", "com.zebrunner.mcloud.mdm"),
		OrgName:      get("MDM_ORG_NAME", "Zebrunner MCloud"),
		TLSCAFile:    get("MDM_TLS_CA_FILE", ""),

		HeadwindURL:       strings.TrimRight(get("HMDM_URL", ""), "/"),
		HeadwindLogin:     get("HMDM_LOGIN", "admin"),
		HeadwindPassword:  get("HMDM_PASSWORD", ""),
		HeadwindPublicURL: strings.TrimRight(get("HMDM_PUBLIC_URL", ""), "/"),
		HeadwindSecret:    get("HMDM_SHARED_SECRET", ""),
		HeadwindTLSCAFile: get("HMDM_TLS_CA_FILE", ""),
		HeadwindTLSPins:   strings.ReplaceAll(get("HMDM_TLS_PIN", ""), " ", ""),
		AgentAPK:          get("MDM_ANDROID_AGENT_APK", "/android/mcloud-mdm-agent.apk"),
		STFURL:            strings.TrimRight(get("MDM_STF_URL", ""), "/"),
		STFToken:          get("MDM_STF_TOKEN", ""),
	}
	switch v := get("MDM_ANDROID_LEGACY_SETUP", "true"); v {
	case "true":
		c.AndroidLegacySetup = true
	case "false":
	default:
		errs = append(errs, fmt.Errorf("MDM_ANDROID_LEGACY_SETUP %q: true or false", v))
	}
	switch v := get("MDM_ENFORCE_NODE_BINDING", "false"); v {
	case "true":
		c.EnforceNodeBinding = true
		if c.STFURL == "" {
			errs = append(errs, errors.New("MDM_ENFORCE_NODE_BINDING=true needs MDM_STF_URL and MDM_STF_TOKEN: STF knows the node of each device"))
		}
	case "false":
	default:
		errs = append(errs, fmt.Errorf("MDM_ENFORCE_NODE_BINDING %q: true or false", v))
	}
	if c.STFURL != "" {
		if u, err := url.Parse(c.STFURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("MDM_STF_URL %q: the http(s) URL of the API of STF, e.g. http://stf-api:3000", c.STFURL))
		}
		if c.STFToken == "" {
			errs = append(errs, errors.New("MDM_STF_TOKEN is empty: an access token of STF (Settings, Keys) for MDM_STF_URL"))
		}
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
	if len(c.AdminToken) < 32 {
		errs = append(errs, errors.New("MDM_ADMIN_TOKEN: a secret of 32+ characters every request of the admin listener needs "+
			"(Authorization: Bearer <token>, or the password of Basic)"))
	}
	if len(c.EnrollToken) < 16 {
		errs = append(errs, errors.New("MDM_ENROLL_TOKEN: a secret of 16+ characters the agents enroll the devices with"))
	}
	if c.TLSCAFile != "" {
		if _, err := os.Stat(c.TLSCAFile); err != nil {
			errs = append(errs, fmt.Errorf("MDM_TLS_CA_FILE: %w", err))
		}
	}
	if c.HeadwindURL != "" {
		if u, err := url.Parse(c.HeadwindURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("HMDM_URL %q: the http(s) URL of Headwind MDM, e.g. http://mdm-hmdm:8080", c.HeadwindURL))
		}
		if c.HeadwindPassword == "" {
			errs = append(errs, errors.New("HMDM_PASSWORD is empty: the password of HMDM_LOGIN in Headwind MDM"))
		}
		if c.HeadwindPublicURL == "" && c.PublicURL != "" {
			c.HeadwindPublicURL = c.PublicURL + "/hmdm"
		}
		// the agent puts the path in front of its requests as one segment (serverProject)
		if u, err := url.Parse(c.HeadwindPublicURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
			!headwindPath.MatchString(u.Path) || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("HMDM_PUBLIC_URL %q: the http(s) URL of Headwind MDM the agents reach, "+
				"with one path segment at most, e.g. https://mcloud.example.com/hmdm", c.HeadwindPublicURL))
		}
		defPort := "31000"
		if strings.HasPrefix(c.HeadwindPublicURL, "https://") {
			defPort = "31443"
		}
		port, err := strconv.Atoi(get("HMDM_MQTT_PORT", defPort))
		if err != nil || port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("HMDM_MQTT_PORT %q: the MQTT port of the agents, 1-65535", getenv("HMDM_MQTT_PORT")))
		}
		c.HeadwindMQTTPort = port
		if c.HeadwindTLSCAFile != "" {
			if _, err := os.Stat(c.HeadwindTLSCAFile); err != nil {
				errs = append(errs, fmt.Errorf("HMDM_TLS_CA_FILE: %w", err))
			}
		}
		if c.HeadwindTLSPins != "" && !validPins(c.HeadwindTLSPins) {
			errs = append(errs, fmt.Errorf("HMDM_TLS_PIN %q: 1 to 4 pins separated by commas, each the base64 of the SHA-256 "+
				"of the public key of the certificate (MCLOUD_TLS_PIN of mcloud-agent)", c.HeadwindTLSPins))
		}
		if len(c.HeadwindSecret) < 16 || strings.ContainsAny(c.HeadwindSecret, ": ") {
			errs = append(errs, errors.New("HMDM_SHARED_SECRET: the SHARED_SECRET of Headwind MDM, 16+ characters without colons or spaces"))
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
