package ratelimit

import (
	"testing"
	"time"
)

func TestFixedWindowBoundsAttemptsAndKeysUntilExpiry(t *testing.T) {
	limiter, err := NewFixedWindow(2, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !limiter.Allow("a", now) || !limiter.Allow("a", now) || limiter.Allow("a", now) {
		t.Fatal("per-key attempt limit was not enforced")
	}
	if !limiter.Allow("b", now) || limiter.Allow("c", now) {
		t.Fatal("key capacity was not enforced")
	}
	if !limiter.Allow("c", now.Add(time.Minute)) {
		t.Fatal("expired key capacity was not reclaimed")
	}
}
