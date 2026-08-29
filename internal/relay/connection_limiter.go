package relay

import (
	"errors"
	"net/http"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
	"github.com/huaxianyan/SyncNotifications-Server/internal/ratelimit"
)

type AuthenticationLimits struct {
	AttemptsPerMinute int
	MaxClientBuckets  int
	MaxConcurrent     int
	FrameTimeout      time.Duration
}

func DefaultAuthenticationLimits() AuthenticationLimits {
	return AuthenticationLimits{
		AttemptsPerMinute: 20,
		MaxClientBuckets:  4096,
		MaxConcurrent:     64,
		FrameTimeout:      5 * time.Second,
	}
}

func (l AuthenticationLimits) validate() error {
	if l.AttemptsPerMinute < 1 || l.MaxClientBuckets < 1 ||
		l.MaxConcurrent < 1 || l.FrameTimeout <= 0 {
		return errors.New("relay authentication limits must be positive")
	}
	return nil
}

type authAttemptLimiter struct {
	windows  *ratelimit.FixedWindow
	resolver clientaddress.Resolver
}

func newAuthAttemptLimiter(
	resolver clientaddress.Resolver,
	limits AuthenticationLimits,
) *authAttemptLimiter {
	windows, err := ratelimit.NewFixedWindow(
		limits.AttemptsPerMinute, limits.MaxClientBuckets, time.Minute)
	if err != nil {
		panic(err)
	}
	return &authAttemptLimiter{windows: windows, resolver: resolver}
}

func (l *authAttemptLimiter) allow(request *http.Request, now time.Time) (bool, error) {
	host, err := l.resolver.Resolve(request)
	if err != nil {
		return false, err
	}
	return l.windows.Allow(host, now), nil
}
