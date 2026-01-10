package ports

import (
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeviceRegistry manages the in-memory state of discovered devices.
type DeviceRegistry interface {
	// ProcessDevice updates or adds a device to the registry.
	// Returns the merged device and whether it was newly discovered (missing or cache invalidated).
	ProcessDevice(device domain.Device) (domain.Device, bool)

	// GetDevice returns a device by MAC.
	GetDevice(mac string) (domain.Device, bool)

	// GetAllDevices returns all known devices.
	GetAllDevices() []domain.Device

	// PruneOldDevices removes devices inactive for more than the given TTL.
	PruneOldDevices(ttl time.Duration) int

	// CleanupStaleConnections degrades connections to "disconnected" if silent for too long.
	CleanupStaleConnections(timeout time.Duration) int

	// GetActiveCount returns the number of devices currently in the registry.
	GetActiveCount() int

	// UpdateSSID records seen SSIDs and their security types.
	UpdateSSID(ssid, security string)

	// GetSSIDs returns all seen SSIDs.
	GetSSIDs() map[string]bool

	// GetSSIDSecurity returns the recorded security for an SSID.
	GetSSIDSecurity(ssid string) (string, bool)

	// Clear wipes all in-memory state.
	Clear()
}
