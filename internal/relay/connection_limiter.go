package relay

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	maxAuthenticationPeers = 4096
	authAttemptsPerMinute  = 20
	maxConcurrentAuth      = 64
)

type authAttemptEntry struct {
	startedAt time.Time
	attempts  int
}

type authAttemptLimiter struct {
	mu    sync.Mutex
	peers map[string]authAttemptEntry
}

func newAuthAttemptLimiter() *authAttemptLimiter {
	return &authAttemptLimiter{peers: make(map[string]authAttemptEntry)}
}

func (l *authAttemptLimiter) allow(request *http.Request, now time.Time) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || host == "" {
		host = request.RemoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.peers[host]
	if exists && now.Sub(entry.startedAt) >= time.Minute {
		delete(l.peers, host)
		exists = false
	}
	if !exists {
		if len(l.peers) >= maxAuthenticationPeers {
			for peer, candidate := range l.peers {
				if now.Sub(candidate.startedAt) >= time.Minute {
					delete(l.peers, peer)
				}
			}
			if len(l.peers) >= maxAuthenticationPeers {
				return false
			}
		}
		l.peers[host] = authAttemptEntry{startedAt: now, attempts: 1}
		return true
	}
	if entry.attempts >= authAttemptsPerMinute {
		return false
	}
	entry.attempts++
	l.peers[host] = entry
	return true
}
