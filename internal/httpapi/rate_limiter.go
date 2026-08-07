package httpapi

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const maxRateLimitPeers = 4096

type fixedWindowEntry struct {
	startedAt time.Time
	attempts  int
}

type registrationRateLimiter struct {
	mu     sync.Mutex
	peers  map[string]fixedWindowEntry
	limit  int
	window time.Duration
}

func newRegistrationRateLimiter() *registrationRateLimiter {
	return &registrationRateLimiter{
		peers: make(map[string]fixedWindowEntry), limit: 10, window: time.Minute,
	}
}

func (l *registrationRateLimiter) allow(r *http.Request, now time.Time) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
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
				return false
			}
		}
		l.peers[host] = fixedWindowEntry{startedAt: now, attempts: 1}
		return true
	}
	if entry.attempts >= l.limit {
		return false
	}
	entry.attempts++
	l.peers[host] = entry
	return true
}
