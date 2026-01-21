package persistence

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// MockStorage implements ports.Storage for testing
type MockStorage struct {
	SavedDevices []domain.Device
	mu           sync.Mutex
}

func (m *MockStorage) SaveDevicesBatch(ctx context.Context, devices []domain.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SavedDevices = append(m.SavedDevices, devices...)
	return nil
}

// Implement other interface methods as no-ops or panics if not needed
func (m *MockStorage) SaveDevice(ctx context.Context, device domain.Device) error { return nil }
func (m *MockStorage) GetDevice(ctx context.Context, mac string) (*domain.Device, error) {
	return &domain.Device{}, nil
}
func (m *MockStorage) GetDevices() ([]domain.Device, error)                         { return nil, nil } // Deprecated/Not in interface? Check ports.
func (m *MockStorage) GetAllDevices(ctx context.Context) ([]domain.Device, error)   { return nil, nil }
func (m *MockStorage) SaveProbe(ctx context.Context, mac string, ssid string) error { return nil }
func (m *MockStorage) SaveAlert(alert domain.Alert) error                           { return nil }
func (m *MockStorage) GetAlerts(limit int) ([]domain.Alert, error)                  { return nil, nil }
func (m *MockStorage) Close() error                                                 { return nil }
func (m *MockStorage) GetDeviceCount() (int, error)                                 { return 0, nil }
func (m *MockStorage) GetAlertCount() (int, error)                                  { return 0, nil }
func (m *MockStorage) GetVendorStats() (map[string]int, error)                      { return nil, nil }
func (m *MockStorage) GetSecurityStats() (map[string]int, error)                    { return nil, nil }
func (m *MockStorage) SaveUser(user domain.User) error                              { return nil }
func (m *MockStorage) GetUser(id string) (domain.User, error)                       { return domain.User{}, nil }
func (m *MockStorage) GetByUsername(username string) (domain.User, error)           { return domain.User{}, nil }

// Vulnerability Persistence mocks
func (m *MockStorage) SaveVulnerability(ctx context.Context, record domain.VulnerabilityRecord) error {
	return nil
}
func (m *MockStorage) GetVulnerabilities(ctx context.Context, filter domain.VulnerabilityFilter) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}
func (m *MockStorage) GetVulnerability(ctx context.Context, id string) (*domain.VulnerabilityRecord, error) {
	return nil, nil
}
func (m *MockStorage) UpdateVulnerabilityStatus(ctx context.Context, id string, status domain.VulnerabilityStatus, notes string) error {
	return nil
}

func TestPersistenceManager_Persist_Batching(t *testing.T) {
	mockStore := &MockStorage{}
	// Create manager with small buffer for testing
	pm := NewPersistenceManager(mockStore, 10)
	pm.batchSize = 5            // Set small batch size
	pm.interval = 1 * time.Hour // Disable timer for this test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm.Start(ctx)

	// Add 4 devices (should not flush yet)
	for i := 0; i < 4; i++ {
		pm.Persist(domain.Device{MAC: "00:00:00:00:00:0" + string(rune('0'+i))})
	}
	time.Sleep(100 * time.Millisecond)

	mockStore.mu.Lock()
	if len(mockStore.SavedDevices) != 0 {
		t.Errorf("Expected 0 saved devices, got %d", len(mockStore.SavedDevices))
	}
	mockStore.mu.Unlock()

	// Add 5th device (should flush)
	pm.Persist(domain.Device{MAC: "00:00:00:00:00:05"})

	// Wait a bit for async flush
	time.Sleep(100 * time.Millisecond)

	mockStore.mu.Lock()
	if len(mockStore.SavedDevices) != 5 {
		t.Errorf("Expected 5 saved devices, got %d", len(mockStore.SavedDevices))
	}
	mockStore.mu.Unlock()
}

func TestPersistenceManager_Persist_Timer(t *testing.T) {
	mockStore := &MockStorage{}
	pm := NewPersistenceManager(mockStore, 10)
	pm.batchSize = 100
	pm.interval = 200 * time.Millisecond // Fast timer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm.Start(ctx)

	// Add 1 device
	pm.Persist(domain.Device{MAC: "AA:BB:CC:DD:EE:FF"})

	time.Sleep(50 * time.Millisecond)
	mockStore.mu.Lock()
	if len(mockStore.SavedDevices) != 0 {
		t.Errorf("Should wait for timer")
	}
	mockStore.mu.Unlock()

	// Wait for timer trigger
	time.Sleep(300 * time.Millisecond)

	mockStore.mu.Lock()
	if len(mockStore.SavedDevices) != 1 {
		t.Errorf("Timer should have flushed the device, got %d", len(mockStore.SavedDevices))
	}
	mockStore.mu.Unlock()
}
