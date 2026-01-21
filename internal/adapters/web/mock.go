package web

import (
	"context"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// MockNetworkService is a mock of ports.NetworkService
type MockNetworkService struct {
	mock.Mock
}

func (m *MockNetworkService) ProcessDevice(ctx context.Context, device domain.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockNetworkService) GetGraph(ctx context.Context) (domain.GraphData, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.GraphData), args.Error(1)
}

func (m *MockNetworkService) TriggerScan(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockNetworkService) GetAlerts(ctx context.Context) ([]domain.Alert, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Alert), args.Error(1)
}

func (m *MockNetworkService) AddRule(ctx context.Context, rule domain.AlertRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockNetworkService) SetPersistenceEnabled(enabled bool) {
	m.Called(enabled)
}

func (m *MockNetworkService) IsPersistenceEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockNetworkService) ResetWorkspace(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockNetworkService) SetChannels(ctx context.Context, channels []int) error {
	args := m.Called(ctx, channels)
	return args.Error(0)
}

func (m *MockNetworkService) GetChannels(ctx context.Context) ([]int, error) {
	args := m.Called(ctx)
	return args.Get(0).([]int), args.Error(1)
}

func (m *MockNetworkService) SetInterfaceChannels(ctx context.Context, iface string, channels []int) error {
	args := m.Called(ctx, iface, channels)
	return args.Error(0)
}

func (m *MockNetworkService) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	args := m.Called(ctx, iface)
	return args.Get(0).([]int), args.Error(1)
}

func (m *MockNetworkService) GetInterfaces(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockNetworkService) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.InterfaceInfo), args.Error(1)
}

func (m *MockNetworkService) StartDeauthAttack(ctx context.Context, config domain.DeauthAttackConfig) (string, error) {
	args := m.Called(ctx, config)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) StopDeauthAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *MockNetworkService) GetDeauthStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.DeauthAttackStatus), args.Error(1)
}

func (m *MockNetworkService) ListDeauthAttacks(ctx context.Context) ([]domain.DeauthAttackStatus, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.DeauthAttackStatus), args.Error(1)
}

// WPS Mock Methods
func (m *MockNetworkService) StartWPSAttack(ctx context.Context, config domain.WPSAttackConfig) (string, error) {
	args := m.Called(ctx, config)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) StopWPSAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *MockNetworkService) GetWPSStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.WPSAttackStatus), args.Error(1)
}

func (m *MockNetworkService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.SystemStats), args.Error(1)
}

// Auth Flood Mock Methods
func (m *MockNetworkService) StartAuthFloodAttack(ctx context.Context, config domain.AuthFloodAttackConfig) (string, error) {
	args := m.Called(ctx, config)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) StopAuthFloodAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *MockNetworkService) GetAuthFloodStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.AuthFloodAttackStatus), args.Error(1)
}

func (m *MockNetworkService) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockDeviceRegistry is a mock of ports.DeviceRegistry (needed for SessionManager mock)
type MockDeviceRegistry struct {
	mock.Mock
}

func (m *MockDeviceRegistry) ProcessDevice(ctx context.Context, device domain.Device) (domain.Device, bool) {
	args := m.Called(ctx, device)
	return args.Get(0).(domain.Device), args.Bool(1)
}

func (m *MockDeviceRegistry) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	args := m.Called(ctx, mac)
	return args.Get(0).(domain.Device), args.Bool(1)
}

func (m *MockDeviceRegistry) GetAllDevices(ctx context.Context) []domain.Device {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Device)
}

func (m *MockDeviceRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int {
	args := m.Called(ctx, ttl)
	return args.Int(0)
}

func (m *MockDeviceRegistry) GetActiveCount(ctx context.Context) int {
	args := m.Called(ctx)
	return args.Int(0)
}

func (m *MockDeviceRegistry) UpdateSSID(ctx context.Context, ssid, security string) {
	m.Called(ctx, ssid, security)
}

func (m *MockDeviceRegistry) GetSSIDs(ctx context.Context) map[string]bool {
	args := m.Called(ctx)
	return args.Get(0).(map[string]bool)
}

func (m *MockDeviceRegistry) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	args := m.Called(ctx, ssid)
	return args.String(0), args.Bool(1)
}

func (m *MockDeviceRegistry) Clear(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockDeviceRegistry) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	return 0 // stub
}

func (m *MockDeviceRegistry) LoadDevice(ctx context.Context, device domain.Device) {
	m.Called(ctx, device)
}
