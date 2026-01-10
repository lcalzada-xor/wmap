package web

import (
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// MockNetworkService is a mock of ports.NetworkService
type MockNetworkService struct {
	mock.Mock
}

func (m *MockNetworkService) ProcessDevice(device domain.Device) {
	m.Called(device)
}

func (m *MockNetworkService) GetGraph() domain.GraphData {
	args := m.Called()
	return args.Get(0).(domain.GraphData)
}

func (m *MockNetworkService) TriggerScan() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockNetworkService) GetAlerts() []domain.Alert {
	args := m.Called()
	return args.Get(0).([]domain.Alert)
}

func (m *MockNetworkService) SetPersistenceEnabled(enabled bool) {
	m.Called(enabled)
}

func (m *MockNetworkService) IsPersistenceEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockNetworkService) ResetWorkspace() {
	m.Called()
}

func (m *MockNetworkService) SetChannels(channels []int) {
	m.Called(channels)
}

func (m *MockNetworkService) GetChannels() []int {
	args := m.Called()
	return args.Get(0).([]int)
}

func (m *MockNetworkService) SetInterfaceChannels(iface string, channels []int) {
	m.Called(iface, channels)
}

func (m *MockNetworkService) GetInterfaceChannels(iface string) []int {
	args := m.Called(iface)
	return args.Get(0).([]int)
}

func (m *MockNetworkService) GetInterfaces() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockNetworkService) GetInterfaceDetails() []domain.InterfaceInfo {
	args := m.Called()
	return args.Get(0).([]domain.InterfaceInfo)
}

func (m *MockNetworkService) StartDeauthAttack(config domain.DeauthAttackConfig) (string, error) {
	args := m.Called(config)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) StopDeauthAttack(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockNetworkService) GetDeauthStatus(id string) (domain.DeauthAttackStatus, error) {
	args := m.Called(id)
	return args.Get(0).(domain.DeauthAttackStatus), args.Error(1)
}

func (m *MockNetworkService) ListDeauthAttacks() []domain.DeauthAttackStatus {
	args := m.Called()
	return args.Get(0).([]domain.DeauthAttackStatus)
}

// WPS Mock Methods
func (m *MockNetworkService) StartWPSAttack(config domain.WPSAttackConfig) (string, error) {
	args := m.Called(config)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) StopWPSAttack(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockNetworkService) GetWPSStatus(id string) (domain.WPSAttackStatus, error) {
	args := m.Called(id)
	return args.Get(0).(domain.WPSAttackStatus), args.Error(1)
}

func (m *MockNetworkService) GetSystemStats() domain.SystemStats {
	args := m.Called()
	return args.Get(0).(domain.SystemStats)
}

// MockDeviceRegistry is a mock of ports.DeviceRegistry (needed for SessionManager mock)
type MockDeviceRegistry struct {
	mock.Mock
}

func (m *MockDeviceRegistry) ProcessDevice(device domain.Device) (domain.Device, bool) {
	args := m.Called(device)
	return args.Get(0).(domain.Device), args.Bool(1)
}

func (m *MockDeviceRegistry) GetDevice(mac string) (domain.Device, bool) {
	args := m.Called(mac)
	return args.Get(0).(domain.Device), args.Bool(1)
}

func (m *MockDeviceRegistry) GetAllDevices() []domain.Device {
	args := m.Called()
	return args.Get(0).([]domain.Device)
}

func (m *MockDeviceRegistry) PruneOldDevices(ttl time.Duration) int {
	args := m.Called(ttl)
	return args.Int(0)
}

func (m *MockDeviceRegistry) GetActiveCount() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockDeviceRegistry) UpdateSSID(ssid, security string) {
	m.Called(ssid, security)
}

func (m *MockDeviceRegistry) GetSSIDs() map[string]bool {
	args := m.Called()
	return args.Get(0).(map[string]bool)
}

func (m *MockDeviceRegistry) GetSSIDSecurity(ssid string) (string, bool) {
	args := m.Called(ssid)
	return args.String(0), args.Bool(1)
}

func (m *MockDeviceRegistry) Clear() {
	m.Called()
}

func (m *MockDeviceRegistry) CleanupStaleConnections(timeout time.Duration) int {
	return 0 // stub
}
