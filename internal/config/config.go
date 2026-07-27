package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	defaultAddress         = "127.0.0.1:8080"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	Address         string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Address:         envOrDefault("NM_ADDRESS", defaultAddress),
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if raw := os.Getenv("NM_SHUTDOWN_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds <= 0 {
			return Config{}, fmt.Errorf("NM_SHUTDOWN_TIMEOUT_SECONDS must be a positive integer")
		}
		cfg.ShutdownTimeout = time.Duration(seconds) * time.Second
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
