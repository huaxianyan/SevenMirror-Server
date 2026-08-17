package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/config"
	"github.com/huaxianyan/SyncNotifications-Server/internal/httpapi"
	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o700); err != nil {
		logger.Error("create data directory", "error", err)
		os.Exit(1)
	}
	store, err := admission.Open(context.Background(), cfg.DatabasePath)
	if err != nil {
		logger.Error("open admission database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	hub := relay.NewHub()
	authenticator, err := admission.NewRelayAuthenticator(store)
	if err != nil {
		logger.Error("configure device authenticator", "error", err)
		os.Exit(1)
	}
	relayHandler, err := relay.NewAuthenticatedWebSocketHandler(hub, authenticator)
	if err != nil {
		logger.Error("configure authenticated relay", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           httpapi.NewProductionHandler(store, relayHandler),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serve := server.ListenAndServe
	transport := "http"
	if cfg.TLSCertFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		serve = func() error { return server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile) }
		transport = "https"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("server listening", "address", cfg.Address, "transport", transport)
		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}
