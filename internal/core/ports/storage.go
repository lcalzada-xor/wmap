package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// Storage defines the behavior for data persistence.
type Storage interface {
	// SaveDevice saves or updates a device in the database.
	SaveDevice(device domain.Device) error
	SaveDevicesBatch(devices []domain.Device) error
	GetDevice(mac string) (*domain.Device, error)

	// GetAllDevices retrieves all known devices.
	GetAllDevices() ([]domain.Device, error)

	// SaveProbe records a new SSID probe for a device.
	SaveProbe(mac string, ssid string) error

	// Close closes the storage connection.
	Close() error
}
