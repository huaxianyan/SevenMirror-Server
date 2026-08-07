package httpapi

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistrationRateLimiterUsesSocketPeerAndResets(t *testing.T) {
	limiter := newRegistrationRateLimiter()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 10; i++ {
		request := httptest.NewRequest("POST", "/v1/devices/register", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		request.Header.Set("X-Forwarded-For", "198.51.100.1")
		if !limiter.allow(request, now) {
			t.Fatalf("attempt %d unexpectedly rejected", i+1)
		}
	}
	blocked := httptest.NewRequest("POST", "/v1/devices/register", nil)
	blocked.RemoteAddr = "192.0.2.10:9999"
	if limiter.allow(blocked, now) {
		t.Fatal("eleventh attempt unexpectedly accepted")
	}
	if !limiter.allow(blocked, now.Add(time.Minute)) {
		t.Fatal("peer did not reset after the fixed window")
	}
}
