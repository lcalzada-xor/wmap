package handlers

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// ScannerService defines the interface required by the API for scanning ops
type ScannerService interface {
	TriggerScan(ctx context.Context) error
	GetInterfaceChannels(ctx context.Context, iface string) ([]int, error)
	GetChannels(ctx context.Context) ([]int, error)
	SetInterfaceChannels(ctx context.Context, iface string, channels []int) error
	SetChannels(ctx context.Context, channels []int) error
	GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error)
	GetSystemStats(ctx context.Context) (domain.SystemStats, error)
}

// ConfigService defines the interface required by the API for config
type ConfigService interface {
	SetPersistenceEnabled(enabled bool)
	IsPersistenceEnabled() bool
}

// API aggregates all functional endpoints
type API struct {
	Scanner ScannerService
	Config  ConfigService
}

// NewAPI creates a new API handler grouping
func NewAPI(scanner ScannerService, config ConfigService) *API {
	return &API{
		Scanner: scanner,
		Config:  config,
	}
}
