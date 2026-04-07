package middleware

import (
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	limiter := NewRateLimiter(3, 1*time.Second)

	// Test: Should allow first 3 requests
	for i := 0; i < 3; i++ {
		if !limiter.Allow("192.168.1.1") {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Test: Should block 4th request
	if limiter.Allow("192.168.1.1") {
		t.Error("4th request should be blocked")
	}

	// Test: Different IP should be allowed
	if !limiter.Allow("192.168.1.2") {
		t.Error("Request from different IP should be allowed")
	}
}

func TestRateLimiter_WindowExpiration(t *testing.T) {
	limiter := NewRateLimiter(2, 500*time.Millisecond)

	// Use up the limit
	limiter.Allow("192.168.1.1")
	limiter.Allow("192.168.1.1")

	// Should be blocked
	if limiter.Allow("192.168.1.1") {
		t.Error("Request should be blocked before window expires")
	}

	// Wait for window to expire
	time.Sleep(600 * time.Millisecond)

	// Should be allowed after window expires
	if !limiter.Allow("192.168.1.1") {
		t.Error("Request should be allowed after window expires")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	limiter := NewRateLimiter(5, 100*time.Millisecond)

	// Make some requests
	limiter.Allow("192.168.1.1")
	limiter.Allow("192.168.1.2")
	limiter.Allow("192.168.1.3")

	// Check initial state
	limiter.mu.Lock()
	initialCount := len(limiter.requests)
	limiter.mu.Unlock()

	if initialCount != 3 {
		t.Errorf("Expected 3 IPs in map, got %d", initialCount)
	}

	// Wait for entries to expire
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup
	limiter.cleanup()

	// Check that old entries were removed
	limiter.mu.Lock()
	afterCleanup := len(limiter.requests)
	limiter.mu.Unlock()

	if afterCleanup != 0 {
		t.Errorf("Expected 0 IPs after cleanup, got %d", afterCleanup)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewRateLimiter(10, 1*time.Second)
	done := make(chan bool)

	// Simulate concurrent requests
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 3; j++ {
				limiter.Allow("192.168.1.1")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}

	// Should have blocked some requests (15 total, limit is 10)
	// Next request should be blocked
	if limiter.Allow("192.168.1.1") {
		t.Error("Should have exceeded limit with concurrent requests")
	}
}

func TestRateLimiter_MultipleIPs(t *testing.T) {
	limiter := NewRateLimiter(2, 1*time.Second)

	// IP 1: Use up limit
	limiter.Allow("192.168.1.1")
	limiter.Allow("192.168.1.1")

	// IP 1: Should be blocked
	if limiter.Allow("192.168.1.1") {
		t.Error("IP 1 should be blocked")
	}

	// IP 2: Should still be allowed
	if !limiter.Allow("192.168.1.2") {
		t.Error("IP 2 should be allowed")
	}
	if !limiter.Allow("192.168.1.2") {
		t.Error("IP 2 second request should be allowed")
	}

	// IP 2: Should now be blocked
	if limiter.Allow("192.168.1.2") {
		t.Error("IP 2 should now be blocked")
	}
}
