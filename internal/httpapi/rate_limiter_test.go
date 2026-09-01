package httpapi

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

func TestRegistrationRateLimiterUsesConfiguredClientAddressAndResets(t *testing.T) {
	limiter := newClientRateLimiter(clientaddress.New(nil), DefaultRateLimits().Membership)
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 10; i++ {
		request := httptest.NewRequest("POST", "/v1/membership/register", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		request.Header.Set("X-Forwarded-For", "198.51.100.1")
		if allowed, err := limiter.allow(request, now); err != nil || !allowed {
			t.Fatalf("attempt %d allowed=%v error=%v", i+1, allowed, err)
		}
	}
	blocked := httptest.NewRequest("POST", "/v1/membership/register", nil)
	blocked.RemoteAddr = "192.0.2.10:9999"
	if allowed, err := limiter.allow(blocked, now); err != nil || allowed {
		t.Fatalf("eleventh attempt allowed=%v error=%v", allowed, err)
	}
	if allowed, err := limiter.allow(blocked, now.Add(time.Minute)); err != nil || !allowed {
		t.Fatalf("reset attempt allowed=%v error=%v", allowed, err)
	}

	trusted := newClientRateLimiter(clientaddress.New([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.10/32"),
	}), DefaultRateLimits().Membership)
	for index, forwarded := range []string{"198.51.100.1", "198.51.100.2"} {
		request := httptest.NewRequest("POST", "/v1/membership/register", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		request.Header.Set("X-Forwarded-For", forwarded)
		if allowed, err := trusted.allow(request, now); err != nil || !allowed {
			t.Fatalf("forwarded client %d allowed=%v error=%v", index+1, allowed, err)
		}
	}
}
