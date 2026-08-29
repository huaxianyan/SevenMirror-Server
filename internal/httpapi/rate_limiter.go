package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
	"github.com/huaxianyan/SyncNotifications-Server/internal/ratelimit"
)

type AttemptLimits struct {
	AttemptsPerMinute int
	MaxClientBuckets  int
}

type RateLimits struct {
	Membership AttemptLimits
	Rotation   AttemptLimits
}

func DefaultRateLimits() RateLimits {
	return RateLimits{
		Membership: AttemptLimits{AttemptsPerMinute: 10, MaxClientBuckets: 4096},
		Rotation:   AttemptLimits{AttemptsPerMinute: 10, MaxClientBuckets: 4096},
	}
}

func (l RateLimits) validate() error {
	if l.Membership.AttemptsPerMinute < 1 || l.Membership.MaxClientBuckets < 1 ||
		l.Rotation.AttemptsPerMinute < 1 || l.Rotation.MaxClientBuckets < 1 {
		return errors.New("HTTP API rate limits must be positive")
	}
	return nil
}

type clientRateLimiter struct {
	windows  *ratelimit.FixedWindow
	resolver clientaddress.Resolver
}

func newClientRateLimiter(
	resolver clientaddress.Resolver,
	limits AttemptLimits,
) *clientRateLimiter {
	window, err := ratelimit.NewFixedWindow(
		limits.AttemptsPerMinute, limits.MaxClientBuckets, time.Minute)
	if err != nil {
		panic(err)
	}
	return &clientRateLimiter{windows: window, resolver: resolver}
}

func (l *clientRateLimiter) allow(r *http.Request, now time.Time) (bool, error) {
	host, err := l.resolver.Resolve(r)
	if err != nil {
		return false, err
	}
	return l.windows.Allow(host, now), nil
}
