package fingerprint

import (
	"testing"
)

func TestOUICache(t *testing.T) {
	cache := NewOUICache(3)

	// Test Set and Get
	cache.Set("00:00:00", "Vendor1")
	cache.Set("11:11:11", "Vendor2")
	cache.Set("22:22:22", "Vendor3")

	if val, ok := cache.Get("00:00:00"); !ok || val != "Vendor1" {
		t.Errorf("Expected Vendor1, got %s", val)
	}

	// Test LRU eviction
	// After Get("00:00:00"), order is: 00:00:00 (most recent), 22:22:22, 11:11:11 (least recent)
	cache.Set("33:33:33", "Vendor4") // Should evict 11:11:11 (least recently used)

	if _, ok := cache.Get("11:11:11"); ok {
		t.Error("Expected 11:11:11 to be evicted")
	}

	if val, ok := cache.Get("00:00:00"); !ok || val != "Vendor1" {
		t.Errorf("Expected Vendor1, got %s", val)
	}

	// Test Len
	if cache.Len() != 3 {
		t.Errorf("Expected cache length 3, got %d", cache.Len())
	}

	// Test Clear
	cache.Clear()
	if cache.Len() != 0 {
		t.Errorf("Expected cache length 0 after clear, got %d", cache.Len())
	}
}

func TestOUICacheConcurrency(t *testing.T) {
	cache := NewOUICache(100)

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := string(rune('0' + id))
				cache.Set(key, "Vendor")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify cache is not corrupted
	if cache.Len() > 100 {
		t.Errorf("Cache exceeded capacity: %d", cache.Len())
	}
}

func BenchmarkOUICacheGet(b *testing.B) {
	cache := NewOUICache(1000)
	cache.Set("00:00:00", "TestVendor")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("00:00:00")
	}
}

func BenchmarkOUICacheSet(b *testing.B) {
	cache := NewOUICache(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set("00:00:00", "TestVendor")
	}
}
