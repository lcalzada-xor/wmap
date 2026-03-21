package mock

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

type MockSniffer struct {
	Out chan<- domain.Device
}

func NewMock(out chan<- domain.Device) *MockSniffer {
	return &MockSniffer{Out: out}
}

func (m *MockSniffer) Start(ctx context.Context) error                                        { return nil }
func (m *MockSniffer) Scan(ctx context.Context, target string) error                          { return nil }
func (m *MockSniffer) SetChannels(ctx context.Context, channels []int)                        {}
func (m *MockSniffer) GetChannels(ctx context.Context) []int                                  { return nil }
func (m *MockSniffer) SetInterfaceChannels(ctx context.Context, iface string, channels []int) {}
func (m *MockSniffer) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	return nil, nil
}
func (m *MockSniffer) GetInterfaces(ctx context.Context) ([]string, error) { return nil, nil }
func (m *MockSniffer) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	return nil, nil
}
func (m *MockSniffer) Lock(ctx context.Context, iface string, channel int) error { return nil }
func (m *MockSniffer) Unlock(ctx context.Context, iface string) error            { return nil }
func (m *MockSniffer) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	return nil
}
func (m *MockSniffer) IsLocked(ctx context.Context, iface string) bool { return false }
func (m *MockSniffer) Close() error                                    { return nil }
