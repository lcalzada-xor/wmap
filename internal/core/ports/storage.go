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

// VulnerabilityRepository handles persistence for security findings.
type VulnerabilityRepository interface {
	SaveVulnerability(ctx context.Context, record domain.VulnerabilityRecord) error
	GetVulnerabilities(ctx context.Context, filter domain.VulnerabilityFilter) ([]domain.VulnerabilityRecord, error)
	GetVulnerability(ctx context.Context, id string) (*domain.VulnerabilityRecord, error)
	UpdateVulnerabilityStatus(ctx context.Context, id string, status domain.VulnerabilityStatus, notes string) error
}

// Storage provides a unified interface for the persistence layer.
// Following the Repository pattern to decouple domain from data access implementations.
type Storage interface {
	DeviceRepository
	ProbeRepository
	VulnerabilityRepository

	// Close ensures all underlying database connections are properly terminated.
	Close() error
}
