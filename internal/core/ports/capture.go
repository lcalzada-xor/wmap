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
	IsLocked(ctx context.Context, iface string) bool
}
