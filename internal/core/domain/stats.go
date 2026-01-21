package domain

import (
	"time"
)

// SystemStats represents an aggregated snapshot of the network state.
type SystemStats struct {
	// Summary Metrics
	DeviceCount int `json:"device_count"`
	AlertCount  int `json:"alert_count"`

	// Distributions
	VendorStats   map[string]int `json:"vendor_stats"`
	SecurityStats map[string]int `json:"security_stats"` // WPA2, WPA3, OPEN...

	// Performance & Health
	AverageRetryRate float64 `json:"global_retry"` // Average packet retry rate across all devices

	// Metadata
	LastUpdated time.Time `json:"updated_at"`
}

// NewSystemStats initializes a new stats object with empty maps to prevent nil access.
func NewSystemStats() SystemStats {
	return SystemStats{
		VendorStats:   make(map[string]int),
		SecurityStats: make(map[string]int),
		LastUpdated:   time.Now(),
	}
}

// IsStale returns true if the stats haven't been updated within the given TTL.
func (s *SystemStats) IsStale(ttl time.Duration) bool {
	return time.Since(s.LastUpdated) > ttl
}
