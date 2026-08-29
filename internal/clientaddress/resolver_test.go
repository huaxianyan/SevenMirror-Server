package clientaddress

import (
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestResolverUsesForwardedAddressOnlyFromConfiguredProxy(t *testing.T) {
	trusted := New([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	untrusted := New(nil)

	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	if address, err := trusted.Resolve(request); err != nil || address != "198.51.100.7" {
		t.Fatalf("trusted address=%q error=%v", address, err)
	}
	if address, err := untrusted.Resolve(request); err != nil || address != "127.0.0.1" {
		t.Fatalf("untrusted address=%q error=%v", address, err)
	}

	request.Header["X-Forwarded-For"] = []string{"198.51.100.7", "198.51.100.8"}
	if _, err := trusted.Resolve(request); !errors.Is(err, ErrInvalidForwardedAddress) {
		t.Fatalf("multiple forwarded values error=%v", err)
	}
	request.Header.Set("X-Forwarded-For", "198.51.100.7, 198.51.100.8")
	if _, err := trusted.Resolve(request); !errors.Is(err, ErrInvalidForwardedAddress) {
		t.Fatalf("forwarded chain error=%v", err)
	}
}
