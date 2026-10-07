package main

import (
	"fmt"
	"os"

	"github.com/huaxianyan/SyncNotifications-Server/internal/config"
	"github.com/huaxianyan/SyncNotifications-Server/internal/readiness"
)

// healthcheckMain is the probe a Compose healthcheck runs. The images ship no
// shell, curl or wget, so the probe is this same binary; see
// internal/readiness for why it cannot rely on ordinary TLS verification.
func healthcheckMain() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readiness probe failed: read configuration: %v\n", err)
		os.Exit(1)
	}
	// The listener address comes from the same configuration the server used, so a
	// deployment that changed NM_ADDRESS needs no second copy of it in the compose
	// healthcheck command.
	if err := readiness.Probe(readiness.Options{
		Address:         cfg.Address,
		CertificateFile: cfg.TLSCertFile,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "readiness probe failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("result=ready")
}
