package httpapi

import (
	"net/http"
	"sync"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
)

const maxRateLimitPeers = 4096

type fixedWindowEntry struct {
	startedAt time.Time
	attempts  int
}

type registrationRateLimiter struct {
	mu       sync.Mutex
	peers    map[string]fixedWindowEntry
	limit    int
	window   time.Duration
	resolver clientaddress.Resolver
}

func newRegistrationRateLimiter(resolver clientaddress.Resolver) *registrationRateLimiter {
	return &registrationRateLimiter{
		peers: make(map[string]fixedWindowEntry), limit: 10, window: time.Minute,
		resolver: resolver,
	}
}

func (l *registrationRateLimiter) allow(r *http.Request, now time.Time) (bool, error) {
	host, err := l.resolver.Resolve(r)
	if err != nil {
		return false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.peers[host]
	if exists && now.Sub(entry.startedAt) >= l.window {
		delete(l.peers, host)
		exists = false
	}
	if !exists {
		if len(l.peers) >= maxRateLimitPeers {
			for peer, candidate := range l.peers {
				if now.Sub(candidate.startedAt) >= l.window {
					delete(l.peers, peer)
				}
			}
			if len(l.peers) >= maxRateLimitPeers {
				return false, nil
			}
		}
		l.peers[host] = fixedWindowEntry{startedAt: now, attempts: 1}
		return true, nil
	}
	if entry.attempts >= l.limit {
		return false, nil
	}
	entry.attempts++
	l.peers[host] = entry
	return true, nil
}
