package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/huaxianyan/SyncNotifications-Server/internal/admission"
	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

func TestLegacyDeviceRegistrationEndpointIsNotMounted(t *testing.T) {
	store, err := admission.Open(context.Background(), t.TempDir()+"/admission.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := NewProductionHandler(
		store,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		clientaddress.New(nil),
		DefaultRateLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/devices/register", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("legacy registration status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()

	NewHandler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if got := res.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := res.Body.String(); got != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q", got)
	}
}

// /readyz has to read the registry, otherwise it cannot tell a relay that is up
// from one that cannot serve, and the Compose healthcheck would only ever repeat
// what /healthz already says.
func TestReadinessReadsTheRegistry(t *testing.T) {
	store, err := admission.Open(context.Background(), t.TempDir()+"/admission.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler, err := NewProductionHandler(
		store,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		clientaddress.New(nil),
		DefaultRateLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Body.String(); got != "{\"status\":\"ready\"}\n" {
		t.Fatalf("body = %q", got)
	}
}

// The store can be closed underneath the handler, which is the case this endpoint
// exists to surface: listening but unable to read the registry.
func TestReadinessReportsAnUnreadableRegistry(t *testing.T) {
	store, err := admission.Open(context.Background(), t.TempDir()+"/admission.db")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewProductionHandler(
		store,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		clientaddress.New(nil),
		DefaultRateLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

// With no store mounted there is nothing to read, so the plain response stands.
func TestReadinessWithoutAStore(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	NewHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}
