// mcloud-mdm is the MDM service of MCloud next to NanoHUB: SCEP of the device identities with one-time challenges,
// the enrollment profile of the agents, the admin UI and the webhook of NanoHUB (README.md).
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zebrunner/mcloud-mdm/internal/admin"
	"github.com/zebrunner/mcloud-mdm/internal/android"
	"github.com/zebrunner/mcloud-mdm/internal/config"
	"github.com/zebrunner/mcloud-mdm/internal/device"
	"github.com/zebrunner/mcloud-mdm/internal/headwind"
	"github.com/zebrunner/mcloud-mdm/internal/nanohub"
	"github.com/zebrunner/mcloud-mdm/internal/scep"
	"github.com/zebrunner/mcloud-mdm/internal/state"
	"github.com/zebrunner/mcloud-mdm/internal/stf"
)

// version is set by the build of the image (-ldflags "-X main.version=<tag>")
var version = "dev"

// banner is the first log line of the service (CONVENTIONS.md#terminal-output): the heavy line, the service, its
// version and the facts, separated by middle dots
func banner(service, ver string, facts ...string) string {
	return strings.Join(append([]string{"\u2501\u2501 " + service + " " + ver}, facts...), " \u00b7 ")
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check the health endpoint of the device listener and exit (the HEALTHCHECK of the image)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	cfg, err := config.Load(os.Getenv)
	if *healthcheck {
		os.Exit(check(cfg))
	}
	if err != nil {
		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		log.Info(banner("mcloud-mdm", version))
		for _, line := range strings.Split(err.Error(), "\n") {
			log.Error("invalid configuration", "problem", line)
		}
		// a restart does not fix the configuration (CONVENTIONS.md#exit-codes)
		os.Exit(0)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	log.Info(banner("mcloud-mdm", version, "device listener "+cfg.DeviceListen))
	if err := run(cfg, log); err != nil {
		log.Error("mcloud-mdm stopped", "err", err)
		os.Exit(1)
	}
}

// check returns 0 when /healthz of the device listener answers
func check(cfg *config.Config) int {
	addr := ":8080"
	if cfg != nil {
		addr = cfg.DeviceListen
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(cfg *config.Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	ca, created, err := scep.LoadOrCreateCA(filepath.Join(cfg.DataDir, "scep"), cfg.OrgName)
	if err != nil {
		return fmt.Errorf("SCEP CA: %w", err)
	}
	if created {
		log.Info("SCEP CA created: give its certificate to NanoHUB (-ca)", "path", filepath.Join(cfg.DataDir, "scep", "ca.pem"))
	}
	st, err := state.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	reg, err := scep.OpenRegistry(filepath.Join(cfg.DataDir, "identities.json"))
	if err != nil {
		return fmt.Errorf("the registry of the device identities: %w", err)
	}
	log.Info("the registry of the device identities: renewals of identities it knows only", "since", reg.Since().Format(time.RFC3339),
		"identities", len(reg.List()))
	scepServer := &scep.Server{CA: ca, Challenges: scep.NewChallenges(cfg.ChallengeTTL), Days: cfg.CertDays,
		Log: log.With("unit", "scep"), Registry: reg, Enrolled: st.Enrolled}
	dev, err := device.New(cfg, scepServer, st, log.With("unit", "device"))
	if err != nil {
		return err
	}
	adm := &admin.Server{Config: cfg, NanoHUB: nanohub.New(cfg.NanoHUBURL, cfg.NanoHUBKey), State: st,
		Log: log.With("unit", "admin"), AnswerTimeout: 30 * time.Second, RefreshDelay: 3 * time.Second, Identities: reg}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.STFURL != "" {
		adm.STF = stf.New(cfg.STFURL, cfg.STFToken)
		dev.Nodes = adm.STF
		go syncNodes(ctx, adm.STF, reg, log.With("unit", "identities"), nodeSyncInterval)
	}
	if cfg.EnforceNodeBinding {
		log.Info("MDM_ENFORCE_NODE_BINDING: the nodes act on the MDM of their own devices only (STF, " + device.NodeHeader + ")")
	}
	dev.Commands = adm
	if cfg.HeadwindURL != "" {
		mgr := &android.Manager{HW: headwind.New(cfg.HeadwindURL, cfg.HeadwindLogin, cfg.HeadwindPassword),
			PublicURL: cfg.HeadwindPublicURL, Secret: cfg.HeadwindSecret, MQTTPort: cfg.HeadwindMQTTPort,
			Pins: cfg.HeadwindTLSPins}
		if cfg.HeadwindTLSCAFile != "" {
			raw, err := os.ReadFile(cfg.HeadwindTLSCAFile)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" {
				return fmt.Errorf("HMDM_TLS_CA_FILE %s: no PEM certificate", cfg.HeadwindTLSCAFile)
			}
			mgr.CA = block.Bytes
		}
		if strings.HasPrefix(cfg.HeadwindPublicURL, "http://") {
			log.Warn("HMDM_PUBLIC_URL is plain http: the API and MQTT of the agents are not encrypted, a lab only")
		}
		if !cfg.AndroidLegacySetup {
			log.Info("MDM_ANDROID_LEGACY_SETUP=false: the nodes get the staged setup of the agents only, the secret in no command line")
		}
		dev.Android, adm.Android = mgr, mgr
		// Headwind MDM may start later: the problem is reported, Android works once it answers
		if err := mgr.HW.Ping(); err != nil {
			log.Warn("Headwind MDM does not answer yet", "url", cfg.HeadwindURL, "err", err)
		}
	}

	servers := []*http.Server{
		{Addr: cfg.DeviceListen, Handler: dev.Handler(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: cfg.AdminListen, Handler: adm.Handler(), ReadHeaderTimeout: 10 * time.Second},
	}
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}(srv)
	}
	log.Info("mcloud-mdm started", "version", version, "device", cfg.DeviceListen, "admin", cfg.AdminListen,
		"public", cfg.PublicURL, "scep", cfg.SCEPURL, "nanohub", cfg.NanoHUBURL, "headwind", cfg.HeadwindURL)

	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
	return err
}

// nodeSyncInterval: how often the revocations of the nodes of STF are read
const nodeSyncInterval = 5 * time.Minute

// syncNodes revokes the device identities of the nodes STF revoked or deleted, at the start and every interval; a
// failure of STF (e.g. an access token that is not of an admin) is logged, nothing is revoked then
func syncNodes(ctx context.Context, client *stf.Client, reg *scep.Registry, log *slog.Logger, interval time.Duration) {
	failing := false
	for {
		nodes, err := client.Nodes()
		switch {
		case err != nil && !failing:
			failing = true
			log.Warn("the nodes of STF are not read: the identities of revoked nodes are not revoked (MDM_STF_TOKEN of an admin)", "err", err)
		case err == nil:
			if failing {
				log.Info("the nodes of STF are read again")
			}
			failing = false
			status := make([]scep.NodeStatus, 0, len(nodes))
			for _, n := range nodes {
				ns := scep.NodeStatus{Label: n.Label, Revoked: n.Status == "revoked"}
				if t, err := time.Parse(time.RFC3339, n.RevokedAt); err == nil {
					ns.RevokedAt = t
				} else if ns.Revoked {
					// a revoked node of an unknown time: all of its identities
					ns.RevokedAt = time.Now()
				}
				status = append(status, ns)
			}
			revoked, err := reg.RevokeNodes(status)
			for _, id := range revoked {
				log.Info("device identity revoked", "serial", id.Serial, "udid", id.UDID, "node", id.Node, "reason", id.Reason)
			}
			if err != nil {
				log.Error("the identities of the revoked nodes", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
