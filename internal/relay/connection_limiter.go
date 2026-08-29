package relay

import (
	"net/http"
	"sync"
	"time"

	"github.com/huaxianyan/SyncNotifications-Server/internal/clientaddress"
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
	mu       sync.Mutex
	peers    map[string]authAttemptEntry
	resolver clientaddress.Resolver
}

func newAuthAttemptLimiter(resolver clientaddress.Resolver) *authAttemptLimiter {
	return &authAttemptLimiter{
		peers: make(map[string]authAttemptEntry), resolver: resolver,
	}
}

func (l *authAttemptLimiter) allow(request *http.Request, now time.Time) (bool, error) {
	host, err := l.resolver.Resolve(request)
	if err != nil {
		return false, err
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
				return false, nil
			}
		}
		l.peers[host] = authAttemptEntry{startedAt: now, attempts: 1}
		return true, nil
	}
	if entry.attempts >= authAttemptsPerMinute {
		return false, nil
	}
	entry.attempts++
	l.peers[host] = entry
	return true, nil
}
