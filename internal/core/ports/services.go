package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// IntelligenceService provides access to processed domain data and system state.
type IntelligenceService interface {
	GetGraph(ctx context.Context) (domain.GraphData, error)
	GetAlerts(ctx context.Context) ([]domain.Alert, error)
	GetSystemStats(ctx context.Context) (domain.SystemStats, error)
	GetDeviceConnectionHistory(ctx context.Context, mac string) ([]domain.ConnectionEvent, error)
	AddRule(ctx context.Context, rule domain.AlertRule) error
}

// NetworkService is the primary entry point for the core logic,
// fulfilling the Interface Segregation Principle by embedding specialized interfaces.
type NetworkService interface {
	NetworkScanner
	IntelligenceService

	ProcessDevice(ctx context.Context, device domain.Device) error
	SetPersistenceEnabled(enabled bool)
	IsPersistenceEnabled() bool
	ResetWorkspace(ctx context.Context) error

	// Close performs a graceful shutdown of all underlying services.
	Close() error
}
