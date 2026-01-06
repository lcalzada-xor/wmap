package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Sniffer defines the interface for packet capture adapters.
type Sniffer interface {
	// Run starts the capture process. It should be blocking or respect context.
	// For this phase, we keep it simple conform to existing Run() error signature.
	// Start starts the capture process. It should be blocking and respect context cancellation.
	// Start starts the capture process. It should be blocking and respect context cancellation.
	Start(ctx context.Context) error
	// Scan performs an active scan (e.g. Probe Requests). target can be empty for broadcast.
	Scan(target string) error
	// SetChannels updates the channel hopping list.
	SetChannels(channels []int)
	// GetChannels returns the current channel hopping list.
	GetChannels() []int
	// Multi-Interface Support
	SetInterfaceChannels(iface string, channels []int)
	GetInterfaceChannels(iface string) []int
	GetInterfaces() []string
	GetInterfaceDetails() []domain.InterfaceInfo
}

// NetworkService defines the core business logic (if we extract it from Server).
// Currently, Server acts as both Web Adapter and "Service".
type NetworkService interface {
	ProcessDevice(device domain.Device)
	GetGraph() domain.GraphData
	TriggerScan() error
	GetAlerts() []domain.Alert
	SetPersistenceEnabled(enabled bool)
	IsPersistenceEnabled() bool
	ResetSession()
	SetChannels(channels []int)
	GetChannels() []int
	// Multi-Interface Support
	SetInterfaceChannels(iface string, channels []int)
	GetInterfaceChannels(iface string) []int
	GetInterfaces() []string
	GetInterfaceDetails() []domain.InterfaceInfo

	// Deauth Attack Methods
	StartDeauthAttack(config domain.DeauthAttackConfig) (string, error)
	StopDeauthAttack(id string) error
	GetDeauthStatus(id string) (domain.DeauthAttackStatus, error)
	ListDeauthAttacks() []domain.DeauthAttackStatus
}
