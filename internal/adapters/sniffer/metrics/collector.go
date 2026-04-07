package metrics

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Collector handles period polling of network interface statistics.
type Collector struct {
	handle            *pcap.Handle
	metrics           domain.InterfaceMetrics
	mu                sync.RWMutex
	appPacketsDropped *atomic.Int64
}

// NewCollector creates a thread-safe metrics aggregator.
func NewCollector(appDrops *atomic.Int64) *Collector {
	return &Collector{
		appPacketsDropped: appDrops,
	}
}

// SetHandle passes the active PCAP capture handle to the collector.
func (c *Collector) SetHandle(h *pcap.Handle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handle = h
}

// Start initiates the 1-second polling background routine.
func (c *Collector) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			h := c.handle
			c.mu.RUnlock()

			if h != nil {
				stats, err := h.Stats()
				if err != nil {
					log.Printf("Failed to get pcap stats: %v", err)
					continue
				}

				c.mu.Lock()
				c.metrics.PacketsReceived = int64(stats.PacketsReceived)
				c.metrics.PacketsDropped = int64(stats.PacketsDropped)
				c.metrics.PacketsIfDropped = int64(stats.PacketsIfDropped)
				if c.appPacketsDropped != nil {
					c.metrics.AppPacketsDropped = c.appPacketsDropped.Load()
				}
				c.mu.Unlock()
			}
		}
	}
}

// GetMetrics returns a clean snapshot of current interface metrics.
func (c *Collector) GetMetrics() domain.InterfaceMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	m := c.metrics
	if c.appPacketsDropped != nil {
		m.AppPacketsDropped = c.appPacketsDropped.Load()
	}
	return m
}
