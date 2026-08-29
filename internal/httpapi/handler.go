package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

type statusResponse struct {
	Status string `json:"status"`
}

func NewHandler() http.Handler {
	return newMux(nil, nil, clientaddress.New(nil))
}

// NewProductionHandler enables authority-controlled membership enrollment,
// credential rotation, and the authenticated relay. These endpoints are not
// mounted unless all admission dependencies are explicit.
func NewProductionHandler(
	store *admission.Store,
	relayHandler http.Handler,
	clientAddresses clientaddress.Resolver,
) http.Handler {
	if store == nil || relayHandler == nil {
		panic("production admission store and relay handler are required")
	}
	return newMux(store, relayHandler, clientAddresses)
}

func newMux(
	store *admission.Store,
	relayHandler http.Handler,
	clientAddresses clientaddress.Resolver,
) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", status("ok"))
	mux.HandleFunc("/readyz", status("ready"))
	if store != nil && relayHandler != nil {
		mux.Handle("/v1/devices/rotate", newCredentialRotationHandler(store, clientAddresses))
		membership := newMembershipHandler(store, clientAddresses)
		mux.HandleFunc("/v1/membership/register", membership.register)
		mux.HandleFunc("/v1/membership/prove", membership.prove)
		mux.HandleFunc("/v1/membership/state", membership.state)
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
