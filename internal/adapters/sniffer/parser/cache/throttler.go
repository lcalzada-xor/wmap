package cache

import (
	"sync"
	"time"
)

const shardCount = 32

// ShardedCache is an optimized lock-striped cache to prevent excessive lock contention
type ShardedCache struct {
	shards [shardCount]shard
}

type shard struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// NewShardedCache initializes a new ShardedCache instance
func NewShardedCache() *ShardedCache {
	sc := &ShardedCache{}
	for i := 0; i < shardCount; i++ {
		sc.shards[i].items = make(map[string]time.Time)
	}
	return sc
}

func (sc *ShardedCache) getShard(key string) *shard {
	// Simple hash
	h := 0
	for i := 0; i < len(key); i++ {
		h = 31*h + int(key[i])
	}
	// positive index
	if h < 0 {
		h = -h
	}
	return &sc.shards[h%shardCount]
}

// ShouldThrottle checks if a key was seen within the given duration. Updates the last seen time.
func (sc *ShardedCache) ShouldThrottle(key string, duration time.Duration) bool {
	shard := sc.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if lastSeen, exists := shard.items[key]; exists {
		if time.Since(lastSeen) < duration {
			return true
		}
	}
	shard.items[key] = time.Now()
	return false
}
