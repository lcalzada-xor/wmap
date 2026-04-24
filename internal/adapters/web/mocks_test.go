package web

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// mockNetworkService for testing handlers
type mockNetworkService struct {
	mock.Mock
}

func (m *mockNetworkService) TriggerScan(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockNetworkService) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	args := m.Called(ctx, iface)
	return args.Get(0).([]int), args.Error(1)
}

func (m *mockNetworkService) GetChannels(ctx context.Context) ([]int, error) {
	args := m.Called(ctx)
	return args.Get(0).([]int), args.Error(1)
}

func (m *mockNetworkService) SetInterfaceChannels(ctx context.Context, iface string, channels []int) error {
	args := m.Called(ctx, iface, channels)
	return args.Error(0)
}

func (m *mockNetworkService) SetChannels(ctx context.Context, channels []int) error {
	args := m.Called(ctx, channels)
	return args.Error(0)
}

func (m *mockNetworkService) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.InterfaceInfo), args.Error(1)
}

func (m *mockNetworkService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.SystemStats), args.Error(1)
}

func (m *mockNetworkService) SetPersistenceEnabled(enabled bool) {
	m.Called(enabled)
}

func (m *mockNetworkService) IsPersistenceEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}
