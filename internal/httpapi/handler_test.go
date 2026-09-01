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
