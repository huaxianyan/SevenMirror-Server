package clientaddress

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
)

var ErrInvalidForwardedAddress = errors.New("invalid forwarded client address")

type Resolver struct {
	trustedProxies []netip.Prefix
}

func New(trustedProxies []netip.Prefix) Resolver {
	return Resolver{trustedProxies: append([]netip.Prefix(nil), trustedProxies...)}
}

func (r Resolver) Resolve(request *http.Request) (string, error) {
	peer, ok := socketPeer(request.RemoteAddr)
	if !ok {
		return request.RemoteAddr, nil
	}
	if !r.isTrusted(peer) {
		return peer.String(), nil
	}
	values := request.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer.String(), nil
	}
	if len(values) != 1 {
		return "", ErrInvalidForwardedAddress
	}
	client, err := netip.ParseAddr(values[0])
	if err != nil || client.Zone() != "" {
		return "", ErrInvalidForwardedAddress
	}
	client = client.Unmap()
	if values[0] != client.String() {
		return "", ErrInvalidForwardedAddress
	}
	return client.String(), nil
}

func (r Resolver) isTrusted(peer netip.Addr) bool {
	for _, prefix := range r.trustedProxies {
		if prefix.Contains(peer) {
			return true
		}
	}
	return false
}

func socketPeer(remoteAddress string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}
