package handlers

import (
	"context"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// mockNetworkService for testing handlers
type mockNetworkService struct {
	mock.Mock
}

func (m *mockNetworkService) GetGraph(ctx context.Context) (domain.GraphData, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.GraphData), args.Error(1)
}

func (m *mockNetworkService) GetDeviceConnectionHistory(ctx context.Context, mac string) ([]domain.ConnectionEvent, error) {
	args := m.Called(ctx, mac)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.ConnectionEvent), args.Error(1)
}

func (m *mockNetworkService) GetAlerts(ctx context.Context) ([]domain.Alert, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Alert), args.Error(1)
}

func (m *mockNetworkService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(domain.SystemStats), args.Error(1)
}

func (m *mockNetworkService) AddRule(ctx context.Context, rule domain.AlertRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *mockNetworkService) TriggerScan(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockNetworkService) GetInterfaces(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockNetworkService) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.InterfaceInfo), args.Error(1)
}

func (m *mockNetworkService) SetChannels(ctx context.Context, channels []int) error {
	args := m.Called(ctx, channels)
	return args.Error(0)
}

func (m *mockNetworkService) GetChannels(ctx context.Context) ([]int, error) {
	args := m.Called(ctx)
	return args.Get(0).([]int), args.Error(1)
}

func (m *mockNetworkService) SetInterfaceChannels(ctx context.Context, iface string, channels []int) error {
	args := m.Called(ctx, iface, channels)
	return args.Error(0)
}

func (m *mockNetworkService) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	args := m.Called(ctx, iface)
	return args.Get(0).([]int), args.Error(1)
}

func (m *mockNetworkService) StartDeauthAttack(ctx context.Context, cfg domain.DeauthAttackConfig) (string, error) {
	args := m.Called(ctx, cfg)
	return args.String(0), args.Error(1)
}

func (m *mockNetworkService) StopDeauthAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *mockNetworkService) GetDeauthStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.DeauthAttackStatus), args.Error(1)
}

func (m *mockNetworkService) ListDeauthAttacks(ctx context.Context) ([]domain.DeauthAttackStatus, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.DeauthAttackStatus), args.Error(1)
}

func (m *mockNetworkService) StartWPSAttack(ctx context.Context, cfg domain.WPSAttackConfig) (string, error) {
	args := m.Called(ctx, cfg)
	return args.String(0), args.Error(1)
}

func (m *mockNetworkService) StopWPSAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *mockNetworkService) GetWPSStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.WPSAttackStatus), args.Error(1)
}

func (m *mockNetworkService) StartAuthFloodAttack(ctx context.Context, cfg domain.AuthFloodAttackConfig) (string, error) {
	args := m.Called(ctx, cfg)
	return args.String(0), args.Error(1)
}

func (m *mockNetworkService) StopAuthFloodAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *mockNetworkService) GetAuthFloodStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.AuthFloodAttackStatus), args.Error(1)
}

func (m *mockNetworkService) StartPMKIDAttack(ctx context.Context, cfg domain.PMKIDAttackConfig) (string, error) {
	args := m.Called(ctx, cfg)
	return args.String(0), args.Error(1)
}

func (m *mockNetworkService) StopPMKIDAttack(ctx context.Context, id string, force bool) error {
	args := m.Called(ctx, id, force)
	return args.Error(0)
}

func (m *mockNetworkService) GetPMKIDStatus(ctx context.Context, id string) (domain.PMKIDAttackStatus, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(domain.PMKIDAttackStatus), args.Error(1)
}

func (m *mockNetworkService) ProcessDevice(ctx context.Context, device domain.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *mockNetworkService) SetPersistenceEnabled(enabled bool) {
	m.Called(enabled)
}

func (m *mockNetworkService) IsPersistenceEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockNetworkService) ResetWorkspace(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockNetworkService) Close() error {
	args := m.Called()
	return args.Error(0)
}

// mockDeviceRegistry for testing
type mockDeviceRegistry struct {
	mock.Mock
}

func (m *mockDeviceRegistry) ProcessDevice(ctx context.Context, device domain.Device) (domain.Device, bool) {
	args := m.Called(ctx, device)
	return args.Get(0).(domain.Device), args.Bool(1)
}

func (m *mockDeviceRegistry) LoadDevice(ctx context.Context, d domain.Device) {
	m.Called(ctx, d)
}

func (m *mockDeviceRegistry) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	args := m.Called(ctx, mac)
	return args.Get(0).(domain.Device), args.Bool(1)
}

func (m *mockDeviceRegistry) GetAllDevices(ctx context.Context) []domain.Device {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Device)
}

func (m *mockDeviceRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int {
	args := m.Called(ctx, ttl)
	return args.Int(0)
}

func (m *mockDeviceRegistry) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	args := m.Called(ctx, timeout)
	return args.Int(0)
}

func (m *mockDeviceRegistry) GetActiveCount(ctx context.Context) int {
	args := m.Called(ctx)
	return args.Int(0)
}

func (m *mockDeviceRegistry) UpdateSSID(ctx context.Context, ssid, security string) {
	m.Called(ctx, ssid, security)
}

func (m *mockDeviceRegistry) GetSSIDs(ctx context.Context) map[string]bool {
	args := m.Called(ctx)
	return args.Get(0).(map[string]bool)
}

func (m *mockDeviceRegistry) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	args := m.Called(ctx, ssid)
	return args.String(0), args.Bool(1)
}

func (m *mockDeviceRegistry) Clear(ctx context.Context) {
	m.Called(ctx)
}
