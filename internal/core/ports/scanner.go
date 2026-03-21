package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

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
