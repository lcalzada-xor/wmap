package network

import (
	"context"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	reg "github.com/lcalzada-xor/wmap/internal/core/services/registry"
)

// deviceTracker stores a minimal snapshot of a device to allow incremental stat updates.
type deviceTracker struct {
	vendor     string
	security   string
	retryRate  float64
	hasPackets bool
}

// StatsService handles calculation and caching of network statistics and graphs.
type StatsService struct {
	registry     ports.DeviceRegistry
	security     ports.SecurityEngine
	graphBuilder *reg.GraphBuilder

	// Reactive Stats State
	stats           domain.SystemStats
	trackers        map[string]deviceTracker
	totalRetrySum   float64
	packetDevCount  int
	statsMu         sync.RWMutex

	// Graph Caching
	cachedGraph     *domain.GraphData
	lastGraphUpdate time.Time
	graphMu         sync.RWMutex
}

// NewStatsService creates a new statistics service and registers it as a registry observer.
func NewStatsService(
	registry ports.DeviceRegistry,
	security ports.SecurityEngine,
) *StatsService {
	s := &StatsService{
		registry:     registry,
		security:     security,
		graphBuilder: reg.NewGraphBuilder(registry),
		stats:        domain.NewSystemStats(),
		trackers:     make(map[string]deviceTracker),
	}

	// Bootstrap initial state
	ctx := context.Background() // Use Background for initialization
	devices := registry.GetAllDevices(ctx)
	for _, d := range devices {
		s.applyDeviceAdded(d)
	}

	// Register as observer for real-time updates
	registry.AddObserver(s)

	return s
}

// GetSystemStats returns the current reactive snapshot of intelligence metrics.
func (s *StatsService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	// Update AlertCount from security engine (this is O(1) usually)
	alerts := s.security.GetAlerts(ctx)
	s.stats.AlertCount = len(alerts)
	s.stats.LastUpdated = time.Now()

	return s.stats, nil
}

// OnDeviceAdded implements ports.DeviceObserver.
func (s *StatsService) OnDeviceAdded(ctx context.Context, device domain.Device) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.applyDeviceAdded(device)
}

// OnDeviceUpdated implements ports.DeviceObserver.
func (s *StatsService) OnDeviceUpdated(ctx context.Context, device domain.Device) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	tracker, ok := s.trackers[device.MAC]
	if !ok {
		// Should not happen if registry is consistent, but handle as addition
		s.applyDeviceAdded(device)
		return
	}

	// 1. Update Vendor Stats if changed
	newVendor := device.Vendor
	if newVendor == "" {
		newVendor = "Unknown"
	}
	if tracker.vendor != newVendor {
		s.stats.VendorStats[tracker.vendor]--
		if s.stats.VendorStats[tracker.vendor] <= 0 {
			delete(s.stats.VendorStats, tracker.vendor)
		}
		s.stats.VendorStats[newVendor]++
		tracker.vendor = newVendor
	}

	// 2. Update Security Stats if changed
	if tracker.security != device.Security {
		if tracker.security != "" {
			s.stats.SecurityStats[tracker.security]--
			if s.stats.SecurityStats[tracker.security] <= 0 {
				delete(s.stats.SecurityStats, tracker.security)
			}
		}
		if device.Security != "" {
			s.stats.SecurityStats[device.Security]++
		}
		tracker.security = device.Security
	}

	// 3. Update Retry Rate Stats
	var newRate float64
	hasPackets := device.PacketsCount > 0
	if hasPackets {
		newRate = float64(device.RetryCount) / float64(device.PacketsCount)
	}

	if tracker.hasPackets {
		s.totalRetrySum -= tracker.retryRate
		if hasPackets {
			s.totalRetrySum += newRate
		} else {
			s.packetDevCount--
		}
	} else if hasPackets {
		s.packetDevCount++
		s.totalRetrySum += newRate
	}

	tracker.retryRate = newRate
	tracker.hasPackets = hasPackets
	s.trackers[device.MAC] = tracker

	if s.packetDevCount > 0 {
		s.stats.AverageRetryRate = s.totalRetrySum / float64(s.packetDevCount)
	} else {
		s.stats.AverageRetryRate = 0
	}
}

// applyDeviceAdded internal helper to initialize device stats.
func (s *StatsService) applyDeviceAdded(d domain.Device) {
	if _, exists := s.trackers[d.MAC]; exists {
		return
	}

	s.stats.DeviceCount++

	v := d.Vendor
	if v == "" {
		v = "Unknown"
	}
	s.stats.VendorStats[v]++

	if d.Security != "" {
		s.stats.SecurityStats[d.Security]++
	}

	tracker := deviceTracker{
		vendor:   v,
		security: d.Security,
	}

	if d.PacketsCount > 0 {
		rate := float64(d.RetryCount) / float64(d.PacketsCount)
		s.totalRetrySum += rate
		s.packetDevCount++
		tracker.retryRate = rate
		tracker.hasPackets = true
	}

	s.trackers[d.MAC] = tracker

	if s.packetDevCount > 0 {
		s.stats.AverageRetryRate = s.totalRetrySum / float64(s.packetDevCount)
	}
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
