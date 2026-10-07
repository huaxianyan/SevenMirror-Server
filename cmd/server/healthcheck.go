package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/config"
)

// The images ship no shell, curl or wget, so a container healthcheck cannot use
// them. `server healthcheck` is the probe a Compose healthcheck runs instead: it
// is the same binary that is already in the image, and it asks the listener that
// this process started.
const (
	probeTimeout     = 3 * time.Second
	probeDialTimeout = 2 * time.Second
)

func healthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	// The listener address is authoritative here, so a deployment that changed
	// NM_ADDRESS does not need to keep a second copy of it in the healthcheck
	// command.
	return probe(cfg.Address, cfg.TLSCertFile != "")
}

// probe requests /readyz from the configured listener and requires 200. Any other
// status, including 503 from a registry that cannot be read, fails the probe.
func probe(address string, tlsEnabled bool) error {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		scheme+"://"+address+"/readyz", nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: probeDialTimeout}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		// A failing probe must not follow a redirect to another service.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("readiness probe must not be redirected")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness probe returned %s", response.Status)
	}
	fmt.Println("result=ready")
	return nil
}

func healthcheckMain() {
	if err := healthcheck(); err != nil {
		fmt.Fprintf(os.Stderr, "readiness probe failed: %v\n", err)
		os.Exit(1)
	}
}
