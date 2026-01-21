package ports

import (
	"context"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeviceRegistry manages the volatile, in-memory state of discovered devices.
// Optimized for fast retrieval and real-time updates during capture.
type DeviceRegistry interface {
	// ProcessDevice updates or adds a device based on newly captured data.
	// Returns the merged result and discovery state.
	ProcessDevice(ctx context.Context, device domain.Device) (merged domain.Device, discovered bool)

	// LoadDevice populates the registry from persistence without triggering discovery logic.
	LoadDevice(ctx context.Context, device domain.Device)

	// GetDevice retrieves a device by MAC address.
	GetDevice(ctx context.Context, mac string) (domain.Device, bool)

	// GetAllDevices returns a snapshot of all current registry entries.
	GetAllDevices(ctx context.Context) []domain.Device

	// Maintenance operations
	PruneOldDevices(ctx context.Context, ttl time.Duration) (count int)
	CleanupStaleConnections(ctx context.Context, timeout time.Duration) (count int)
	GetActiveCount(ctx context.Context) int

	// SSID Intelligence
	UpdateSSID(ctx context.Context, ssid, security string)
	GetSSIDs(ctx context.Context) map[string]bool
	GetSSIDSecurity(ctx context.Context, ssid string) (security string, found bool)

	// Clear resets the registry state.
	Clear(ctx context.Context)
}
