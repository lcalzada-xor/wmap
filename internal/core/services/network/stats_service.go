package network

import (
	"context"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	reg "github.com/lcalzada-xor/wmap/internal/core/services/registry"
)

// StatsService handles calculation and caching of network statistics and graphs.
type StatsService struct {
	registry     ports.DeviceRegistry
	security     ports.SecurityEngine
	graphBuilder *reg.GraphBuilder

	// Graph Caching
	cachedGraph     *domain.GraphData
	lastGraphUpdate time.Time
	graphMu         sync.RWMutex
}

// NewStatsService creates a new statistics service.
func NewStatsService(
	registry ports.DeviceRegistry,
	security ports.SecurityEngine,
) *StatsService {
	return &StatsService{
		registry:     registry,
		security:     security,
		graphBuilder: reg.NewGraphBuilder(registry),
	}
}

// GetSystemStats calculates aggregate intelligence metrics.
func (s *StatsService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	devices := s.registry.GetAllDevices(ctx)
	stats := domain.NewSystemStats()

	alerts := s.security.GetAlerts(ctx)
	stats.AlertCount = len(alerts)

	stats.DeviceCount = len(devices)

	var totalRetry float64
	var packetDevices int

	for _, d := range devices {
		// Vendor
		v := d.Vendor
		if v == "" {
			v = "Unknown"
		}
		stats.VendorStats[v]++

		// Security
		if d.Security != "" {
			stats.SecurityStats[d.Security]++
		}

		// Global Retry Rate
		if d.PacketsCount > 0 {
			rate := float64(d.RetryCount) / float64(d.PacketsCount)
			totalRetry += rate
			packetDevices++
		}
	}

	if packetDevices > 0 {
		stats.AverageRetryRate = totalRetry / float64(packetDevices)
	}

	return stats, nil
}

// GetGraph returns the graph projection for visualization with caching.
func (s *StatsService) GetGraph(ctx context.Context) (domain.GraphData, error) {
	s.graphMu.RLock()
	// Cache for 2 seconds
	if s.cachedGraph != nil && time.Since(s.lastGraphUpdate) < 2*time.Second {
		defer s.graphMu.RUnlock()
		return *s.cachedGraph, nil
	}
	s.graphMu.RUnlock()

	s.graphMu.Lock()
	defer s.graphMu.Unlock()

	// Double-check locking optimization
	if s.cachedGraph != nil && time.Since(s.lastGraphUpdate) < 2*time.Second {
		return *s.cachedGraph, nil
	}

	g := s.graphBuilder.BuildGraph(ctx)
	s.cachedGraph = &g
	s.lastGraphUpdate = time.Now()
	// Note: BuildGraph returns a value, so we take address for cache but return value
	return g, nil
}
