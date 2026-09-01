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
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
	"github.com/huaxianyan/SyncNotifications-Server/internal/config"
	"github.com/huaxianyan/SyncNotifications-Server/internal/httpapi"
	"github.com/huaxianyan/SyncNotifications-Server/internal/relay"
)

func configuredHTTPRateLimits(overrides config.AbuseLimitOverrides) httpapi.RateLimits {
	limits := httpapi.DefaultRateLimits()
	if overrides.MembershipAttemptsPerMinute != 0 {
		limits.Membership.AttemptsPerMinute = overrides.MembershipAttemptsPerMinute
	}
	if overrides.RotationAttemptsPerMinute != 0 {
		limits.Rotation.AttemptsPerMinute = overrides.RotationAttemptsPerMinute
	}
	if overrides.RateLimitMaxClientBuckets != 0 {
		limits.Membership.MaxClientBuckets = overrides.RateLimitMaxClientBuckets
		limits.Rotation.MaxClientBuckets = overrides.RateLimitMaxClientBuckets
	}
	return limits
}

func configuredRelayAuthenticationLimits(
	overrides config.AbuseLimitOverrides,
) relay.AuthenticationLimits {
	limits := relay.DefaultAuthenticationLimits()
	if overrides.RelayAuthAttemptsPerMinute != 0 {
		limits.AttemptsPerMinute = overrides.RelayAuthAttemptsPerMinute
	}
	if overrides.RelayAuthMaxClientBuckets != 0 {
		limits.MaxClientBuckets = overrides.RelayAuthMaxClientBuckets
	}
	if overrides.RelayAuthMaxConcurrent != 0 {
		limits.MaxConcurrent = overrides.RelayAuthMaxConcurrent
	}
	if overrides.RelayAuthFrameTimeout != 0 {
		limits.FrameTimeout = overrides.RelayAuthFrameTimeout
	}
	return limits
}

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

	hub, err := relay.NewHub(store, store)
	if err != nil {
		logger.Error("configure durable relay", "error", err)
		os.Exit(1)
	}
	authenticator, err := admission.NewRelayAuthenticator(store)
	if err != nil {
		logger.Error("configure device authenticator", "error", err)
		os.Exit(1)
	}
	clientAddresses := clientaddress.New(cfg.TrustedProxyCIDRs)
	relayLimits := configuredRelayAuthenticationLimits(cfg.AbuseLimits)
	relayHandler, err := relay.NewAuthenticatedWebSocketHandler(
		hub, authenticator, clientAddresses, relayLimits)
	if err != nil {
		logger.Error("configure authenticated relay", "error", err)
		os.Exit(1)
	}

	apiLimits := configuredHTTPRateLimits(cfg.AbuseLimits)
	productionHandler, err := httpapi.NewProductionHandler(
		store, relayHandler, clientAddresses, apiLimits)
	if err != nil {
		logger.Error("configure admission rate limits", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           productionHandler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.RequestReadTimeout,
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
		err := relay.RunAuthorizationMonitor(
			ctx,
			hub,
			250*time.Millisecond,
			func(checkContext context.Context, session relay.ConnectedSession) (bool, error) {
				var workspaceID admission.WorkspaceID
				var deviceID admission.DeviceID
				copy(workspaceID[:], session.Peer.WorkspaceID[:])
				copy(deviceID[:], session.Peer.DeviceID[:])
				authorized, err := store.IsSessionAuthorized(
					checkContext, workspaceID, deviceID, session.CredentialVersion)
				if err != nil {
					logger.Warn("device authorization check failed; disconnecting active peer")
				}
				return authorized, err
			},
		)
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("authorization monitor stopped", "error", err)
			stop()
		}
	}()

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
