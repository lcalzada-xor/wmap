package fingerprint

import (
	"container/list"
	"context"
	"sync"
	"sync/atomic"
)

// OUICache implements an LRU (Least Recently Used) cache for OUI lookups
// It implements the VendorRepository interface and can be used as a caching layer
type OUICache struct {
	capacity   int
	cache      map[string]*list.Element
	lru        *list.List
	mu         sync.RWMutex
	hits       atomic.Int64
	misses     atomic.Int64
	evictions  atomic.Int64
	underlying VendorRepository // Optional underlying repository for cache-through
}

type cacheEntry struct {
	key   string
	value string
}

// NewOUICache creates a new LRU cache with the specified capacity
func NewOUICache(capacity int) *OUICache {
	return &OUICache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// NewCachingRepository creates a caching repository that wraps an underlying repository
func NewCachingRepository(capacity int, underlying VendorRepository) *OUICache {
	return &OUICache{
		capacity:   capacity,
		cache:      make(map[string]*list.Element),
		lru:        list.New(),
		underlying: underlying,
	}
}

// LookupVendor implements VendorRepository interface
func (c *OUICache) LookupVendor(ctx context.Context, mac MACAddress) (string, error) {
	oui := mac.OUI()

	// Try cache first
	if vendor, ok := c.get(oui); ok {
		c.hits.Add(1)
		return vendor, nil
	}

	c.misses.Add(1)

	// If no underlying repository, return not found
	if c.underlying == nil {
		return "", ErrVendorNotFound
	}

	// Query underlying repository
	vendor, err := c.underlying.LookupVendor(ctx, mac)
	if err != nil {
		return "", err
	}

	// Cache the result
	c.set(oui, vendor)
	return vendor, nil
}

// Get retrieves a value from the cache (legacy method for backward compatibility)
func (c *OUICache) Get(key string) (string, bool) {
	return c.get(key)
}

// get retrieves a value from the cache (internal method)
func (c *OUICache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		c.lru.MoveToFront(elem)
		return elem.Value.(*cacheEntry).value, true
	}
	return "", false
}

// Set adds or updates a value in the cache (legacy method for backward compatibility)
func (c *OUICache) Set(key, value string) {
	c.set(key, value)
}

// set adds or updates a value in the cache (internal method)
func (c *OUICache) set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry
	if elem, ok := c.cache[key]; ok {
		c.lru.MoveToFront(elem)
		elem.Value.(*cacheEntry).value = value
		return
	}

	// Add new entry
	entry := &cacheEntry{key, value}
	elem := c.lru.PushFront(entry)
	c.cache[key] = elem

	// Evict oldest if over capacity
	if c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			delete(c.cache, oldest.Value.(*cacheEntry).key)
			c.evictions.Add(1)
		}
	}
}

// Len returns the current number of items in the cache
func (c *OUICache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lru.Len()
}

// Clear removes all items from the cache
func (c *OUICache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*list.Element)
	c.lru = list.New()
}

// Close implements VendorRepository interface
func (c *OUICache) Close() error {
	c.Clear()
	if c.underlying != nil {
		return c.underlying.Close()
	}
	return nil
}

// Stats returns cache statistics
func (c *OUICache) Stats() CacheStats {
	return CacheStats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
		Size:      c.Len(),
		Capacity:  c.capacity,
	}
}

// CacheStats contains cache performance metrics
type CacheStats struct {
	Hits      int64
	Misses    int64
	Evictions int64
	Size      int
	Capacity  int
}

// HitRate returns the cache hit rate as a percentage
func (s CacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}
