package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/adminservice"
	"github.com/huaxianyan/SyncNotifications-Server/internal/adminweb"
	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := adminweb.LoadRuntimeConfig()
	if err != nil {
		logger.Error("invalid admin configuration", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(config.DatabasePath), 0o700); err != nil {
		logger.Error("create data directory", "error", err)
		os.Exit(1)
	}
	store, err := admission.Open(context.Background(), config.DatabasePath)
	if err != nil {
		logger.Error("open admission database", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	management, err := adminservice.New(store, config.AuthorityKeyDirectory)
	if err != nil {
		logger.Error("configure administration", "error", err)
		os.Exit(1)
	}

	loginCode := make([]byte, 32)
	if _, err := rand.Read(loginCode); err != nil {
		logger.Error("generate admin login code", "error", err)
		os.Exit(1)
	}
	encodedLoginCode := base64.RawURLEncoding.EncodeToString(loginCode)
	clear(loginCode)
	encodedLoginCodeBytes := []byte(encodedLoginCode)
	handler, err := adminweb.NewHandler(management, adminweb.HandlerConfig{
		LoginCode: encodedLoginCodeBytes, ExpectedOrigin: config.ExpectedOrigin,
	})
	clear(encodedLoginCodeBytes)
	if err != nil {
		logger.Error("configure admin handler", "error", err)
		os.Exit(1)
	}
	fmt.Printf("admin_login_code=%s\n", encodedLoginCode)
	encodedLoginCode = ""

	server := &http.Server{
		Addr: config.Address, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("admin server listening", "address", config.Address,
			"expected_origin", config.ExpectedOrigin)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin server stopped unexpectedly", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownContext, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Error("admin server shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("admin server stopped")
}
