package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeviceRepository handles persistence for discovered devices.
type DeviceRepository interface {
	SaveDevice(ctx context.Context, device domain.Device) error
	SaveDevicesBatch(ctx context.Context, devices []domain.Device) error
	GetDevice(ctx context.Context, mac string) (*domain.Device, error)
	GetAllDevices(ctx context.Context) ([]domain.Device, error)
}

// ProbeRepository handles persistence for SSID probes and associated metadata.
type ProbeRepository interface {
	SaveProbe(ctx context.Context, mac string, ssid string) error
}

// ConnectionHistoryRepository handles persistence for device connection events.
type ConnectionHistoryRepository interface {
	SaveConnectionEvent(ctx context.Context, event domain.ConnectionEvent) error
	SaveConnectionEventsBatch(ctx context.Context, events []domain.ConnectionEvent) error
	GetConnectionHistory(ctx context.Context, mac string, limit int) ([]domain.ConnectionEvent, error)
}

// Storage provides a unified interface for the persistence layer.
// Following the Repository pattern to decouple domain from data access implementations.
type Storage interface {
	DeviceRepository
	ProbeRepository
	ConnectionHistoryRepository

	// Close ensures all underlying database connections are properly terminated.
	Close() error
}
