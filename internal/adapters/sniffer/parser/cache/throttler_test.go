package cache

import (
	"testing"
	"time"
)

func TestShardedCache_ShouldThrottle(t *testing.T) {
	sc := NewShardedCache()
	key := "test-mac"

	// Initial check: should NOT throttle
	if sc.ShouldThrottle(key, 100*time.Millisecond) {
		t.Errorf("Expected ShouldThrottle to return false on first check")
	}

	// Immediate follow-up: SHOULD throttle
	if !sc.ShouldThrottle(key, 100*time.Millisecond) {
		t.Errorf("Expected ShouldThrottle to return true on second check within duration")
	}

	// Wait for duration to pass
	time.Sleep(110 * time.Millisecond)

	// After duration: should NOT throttle
	if sc.ShouldThrottle(key, 100*time.Millisecond) {
		t.Errorf("Expected ShouldThrottle to return false after duration passed")
	}
}

func TestShardedCache_MultiKeys(t *testing.T) {
	sc := NewShardedCache()
	key1 := "mac1"
	key2 := "mac2"

	sc.ShouldThrottle(key1, 1*time.Second)

	// key2 should not be throttled by key1
	if sc.ShouldThrottle(key2, 1*time.Second) {
		t.Errorf("Expected key2 not to be throttled by key1")
	}
}
