package sniffer

// Re-export types from subpackages for backward compatibility
import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	manager "github.com/lcalzada-xor/wmap/internal/adapters/sniffer/manager"
	testing "github.com/lcalzada-xor/wmap/internal/adapters/sniffer/testing"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/geo"
)

// SnifferManager is re-exported from the manager subpackage
type SnifferManager = manager.SnifferManager

// NewManager creates a new SnifferManager
func NewManager(interfaces []string, dwell int, debug bool, loc geo.Provider, repo fingerprint.VendorRepository) *SnifferManager {
	return manager.NewManager(interfaces, dwell, debug, loc, repo)
}

// MockSniffer is re-exported from the testing subpackage
type MockSniffer = testing.MockSniffer

// NewMock creates a new MockSniffer
func NewMock(out chan<- domain.Device, loc geo.Provider) *MockSniffer {
	return testing.NewMock(out, loc)
}

// Ensure MockSniffer implements the Sniffer interface
var _ interface {
	Start(ctx context.Context) error
	Scan(target string) error
	SetChannels(channels []int)
	GetChannels() []int
	SetInterfaceChannels(iface string, channels []int)
	GetInterfaceChannels(iface string) []int
	GetInterfaces() []string
	GetInterfaceDetails() []domain.InterfaceInfo
	Lock(iface string, channel int) error
	Unlock(iface string) error
	ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error
	Close()
} = (*MockSniffer)(nil)
