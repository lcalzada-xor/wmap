package fingerprint

import (
	"container/list"
	"sync"
)

// OUICache implements an LRU (Least Recently Used) cache for OUI lookups
type OUICache struct {
	capacity int
	cache    map[string]*list.Element
	lru      *list.List
	mu       sync.RWMutex
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

// Get retrieves a value from the cache
func (c *OUICache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if elem, ok := c.cache[key]; ok {
		c.lru.MoveToFront(elem)
		return elem.Value.(*cacheEntry).value, true
	}
	return "", false
}

// Set adds or updates a value in the cache
func (c *OUICache) Set(key, value string) {
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
