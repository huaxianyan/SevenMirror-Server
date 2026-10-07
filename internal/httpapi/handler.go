package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

type statusResponse struct {
	Status string `json:"status"`
}

// readyCheckTimeout bounds the registry read behind /readyz. It is short on
// purpose: the probe shares a single SQLite connection with request handling
// (Store uses SetMaxOpenConns(1)), so a stuck read must not hold the endpoint
// open longer than a probe would wait.
const readyCheckTimeout = 2 * time.Second

func NewHandler() http.Handler {
	return newMux(nil, nil, nil, nil)
}

// NewProductionHandler enables authority-controlled membership enrollment,
// credential rotation, the authenticated relay, and workspace preference
// storage. These endpoints are not mounted unless all admission dependencies
// are explicit.
func NewProductionHandler(
	store *admission.Store,
	relayHandler http.Handler,
	clientAddresses clientaddress.Resolver,
	limits RateLimits,
) (http.Handler, error) {
	if store == nil || relayHandler == nil {
		return nil, errors.New("production admission store and relay handler are required")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	membershipLimiter := newClientRateLimiter(clientAddresses, limits.Membership)
	rotationLimiter := newClientRateLimiter(clientAddresses, limits.Rotation)
	return newMux(store, relayHandler, membershipLimiter, rotationLimiter), nil
}

func newMux(
	store *admission.Store,
	relayHandler http.Handler,
	membershipLimiter *clientRateLimiter,
	rotationLimiter *clientRateLimiter,
) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", status("ok"))
	// /readyz reports whether the registry can serve a read. When no store is
	// mounted there is nothing to check, so it keeps the plain status response
	// that NewHandler uses.
	mux.HandleFunc("/readyz", readiness(store))
	if store != nil && relayHandler != nil {
		mux.Handle("/v1/devices/rotate", newCredentialRotationHandler(store, rotationLimiter))
		membership := newMembershipHandler(store, membershipLimiter)
		mux.HandleFunc("/v1/membership/register", membership.register)
		mux.HandleFunc("/v1/membership/prove", membership.prove)
		mux.HandleFunc("/v1/membership/state", membership.state)
		preferences := newPreferenceHandler(store)
		mux.HandleFunc("/v1/workspace/preferences/read", preferences.read)
		mux.HandleFunc("/v1/workspace/preferences/write", preferences.write)
		mux.Handle("/v1/relay", relayHandler)
	}
	return securityHeaders(mux)
}

func status(value string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(statusResponse{Status: value})
	}
}

// readiness reports whether the process can serve from its registry. A relay that
// listens but cannot reach its registry answers 503, which is what lets a Compose
// healthcheck distinguish the two: a process that is up from one that is usable.
func readiness(store *admission.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
			defer cancel()
			if err := store.HealthCheck(ctx); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(statusResponse{Status: "unavailable"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(statusResponse{Status: "ready"})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
