package ratelimit

import (
	"errors"
	"sync"
	"time"
)

type FixedWindow struct {
	mu         sync.Mutex
	entries    map[string]entry
	limit      int
	maxEntries int
	window     time.Duration
}

type entry struct {
	startedAt time.Time
	attempts  int
}

func NewFixedWindow(limit int, maxEntries int, window time.Duration) (*FixedWindow, error) {
	if limit < 1 || maxEntries < 1 || window <= 0 {
		return nil, errors.New("fixed-window limits must be positive")
	}
	return &FixedWindow{
		entries: make(map[string]entry), limit: limit, maxEntries: maxEntries, window: window,
	}, nil
}

func (l *FixedWindow) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	current, exists := l.entries[key]
	if exists && now.Sub(current.startedAt) >= l.window {
		delete(l.entries, key)
		exists = false
	}
	if !exists {
		if len(l.entries) >= l.maxEntries {
			for candidateKey, candidate := range l.entries {
				if now.Sub(candidate.startedAt) >= l.window {
					delete(l.entries, candidateKey)
				}
			}
			if len(l.entries) >= l.maxEntries {
				return false
			}
		}
		l.entries[key] = entry{startedAt: now, attempts: 1}
		return true
	}
	if current.attempts >= l.limit {
		return false
	}
	current.attempts++
	l.entries[key] = current
	return true
}
