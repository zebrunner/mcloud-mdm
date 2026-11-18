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
		for _, line := range strings.Split(err.Error(), "\n") {
			log.Error("invalid configuration", "problem", line)
		}
		// a restart does not fix the configuration (CONVENTIONS.md#exit-codes)
		os.Exit(0)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
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
	scepServer := &scep.Server{CA: ca, Challenges: scep.NewChallenges(cfg.ChallengeTTL), Days: cfg.CertDays, Log: log.With("unit", "scep")}
	dev, err := device.New(cfg, scepServer, st, log.With("unit", "device"))
	if err != nil {
		return err
	}
	adm := &admin.Server{Config: cfg, NanoHUB: nanohub.New(cfg.NanoHUBURL, cfg.NanoHUBKey), State: st,
		Log: log.With("unit", "admin"), AnswerTimeout: 30 * time.Second, RefreshDelay: 3 * time.Second}
	if cfg.STFURL != "" {
		adm.STF = stf.New(cfg.STFURL, cfg.STFToken)
	}
	dev.Commands = adm
	if cfg.HeadwindURL != "" {
		mgr := &android.Manager{HW: headwind.New(cfg.HeadwindURL, cfg.HeadwindLogin, cfg.HeadwindPassword),
			PublicURL: cfg.HeadwindPublicURL, Secret: cfg.HeadwindSecret, MQTTPort: cfg.HeadwindMQTTPort}
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
