package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Sniffer defines the abstraction for a network capture device.
// It combines packet capture capabilities with hardware control (channel locking).
type Sniffer interface {
	// Start begins the capture process. It is blocking and respects context cancellation.
	Start(ctx context.Context) error

	// Scan triggers an active scan (e.g., Probe Requests).
	Scan(ctx context.Context, target string) error

	// Interface Management
	GetInterfaces(ctx context.Context) ([]string, error)
	GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error)

	// Channel Management
	SetChannels(ctx context.Context, channels []int)
	GetChannels(ctx context.Context) []int
	SetInterfaceChannels(ctx context.Context, iface string, channels []int)
	GetInterfaceChannels(ctx context.Context, iface string) ([]int, error)

	// ChannelLocking provides exclusive access to a radio channel for specific operations (like attacks).
	ChannelLocking

	// Close releases all hardware resources.
	Close() error
}

// ChannelLocking defines the capability to lock a radio interface to a specific channel.
type ChannelLocking interface {
	Lock(ctx context.Context, iface string, channel int) error
	Unlock(ctx context.Context, iface string) error
	ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error
}

// NetworkScanner manages the higher-level scanning logic and hardware orchestration.
type NetworkScanner interface {
	TriggerScan(ctx context.Context) error
	GetInterfaces(ctx context.Context) ([]string, error)
	GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error)
	SetChannels(ctx context.Context, channels []int) error
	GetChannels(ctx context.Context) ([]int, error)
	SetInterfaceChannels(ctx context.Context, iface string, channels []int) error
	GetInterfaceChannels(ctx context.Context, iface string) ([]int, error)
}

// AttackManager coordinates the lifecycle of various security assessments.
type AttackManager interface {
	// Deauth Attacks
	StartDeauthAttack(ctx context.Context, config domain.DeauthAttackConfig) (string, error)
	StopDeauthAttack(ctx context.Context, id string, force bool) error
	GetDeauthStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error)
	ListDeauthAttacks(ctx context.Context) ([]domain.DeauthAttackStatus, error)

	// WPS Attacks
	StartWPSAttack(ctx context.Context, config domain.WPSAttackConfig) (string, error)
	StopWPSAttack(ctx context.Context, id string, force bool) error
	GetWPSStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error)

	// Auth Flood Attacks
	StartAuthFloodAttack(ctx context.Context, config domain.AuthFloodAttackConfig) (string, error)
	StopAuthFloodAttack(ctx context.Context, id string, force bool) error
	GetAuthFloodStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error)
}

// IntelligenceService provides access to processed domain data and system state.
type IntelligenceService interface {
	GetGraph(ctx context.Context) (domain.GraphData, error)
	GetAlerts(ctx context.Context) ([]domain.Alert, error)
	GetSystemStats(ctx context.Context) (domain.SystemStats, error)
	AddRule(ctx context.Context, rule domain.AlertRule) error
}

// NetworkService is the primary entry point for the core logic,
// fulfilling the Interface Segregation Principle by embedding specialized interfaces.
type NetworkService interface {
	NetworkScanner
	AttackManager
	IntelligenceService

	ProcessDevice(ctx context.Context, device domain.Device) error
	SetPersistenceEnabled(enabled bool)
	IsPersistenceEnabled() bool
	ResetWorkspace(ctx context.Context) error

	// Close performs a graceful shutdown of all underlying services.
	Close() error
}
