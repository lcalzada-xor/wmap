package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRegistry for SecurityEngine tests
type MockRegistry struct {
	mock.Mock
}

func (m *MockRegistry) GetSSIDSecurity(ssid string) (string, bool) {
	args := m.Called(ssid)
	return args.String(0), args.Bool(1)
}

// Implement other interface methods as stubs...
func (m *MockRegistry) ProcessDevice(device domain.Device) (domain.Device, bool) {
	return device, false
}
func (m *MockRegistry) GetDevice(mac string) (domain.Device, bool) { return domain.Device{}, false }
func (m *MockRegistry) GetAllDevices() []domain.Device {
	args := m.Called()
	return args.Get(0).([]domain.Device)
}
func (m *MockRegistry) PruneOldDevices(ttl time.Duration) int             { return 0 }
func (m *MockRegistry) GetActiveCount() int                               { return 0 }
func (m *MockRegistry) UpdateSSID(ssid, security string)                  {}
func (m *MockRegistry) GetSSIDs() map[string]bool                         { return nil }
func (m *MockRegistry) Clear()                                            {}
func (m *MockRegistry) CleanupStaleConnections(timeout time.Duration) int { return 0 }

// TestIntelligenceFeatures verifies the new detection logic
func TestSecurityEngine_Intelligence(t *testing.T) {
	mockRegistry := new(MockRegistry)
	engine := NewSecurityEngine(mockRegistry)

	t.Run("High Retry Rate Detection", func(t *testing.T) {
		device := domain.Device{
			MAC:          "00:11:22:33:44:55",
			PacketsCount: 100,
			RetryCount:   30, // 30% > 20% Threshold
			Behavioral:   &domain.BehavioralProfile{},
		}

		engine.Analyze(device)

		assert.Equal(t, 0.3, device.Behavioral.AnomalyDetails["HIGH_RETRY_RATE"])

		alerts := engine.GetAlerts()
		assert.NotEmpty(t, alerts)
		assert.Equal(t, "HIGH_RETRY_RATE", alerts[0].Subtype)
	})

	t.Run("Karma Detection", func(t *testing.T) {
		device := domain.Device{
			MAC:  "AA:BB:CC:DD:EE:FF",
			Type: "ap",
			ProbedSSIDs: map[string]time.Time{
				"Home": time.Now(), "Guest": time.Now(), "Starbucks": time.Now(),
				"FreeWifi": time.Now(), "Airport": time.Now(), "Hotel": time.Now(), // > 5
			},
			Behavioral: &domain.BehavioralProfile{},
		}

		engine.Analyze(device)

		assert.Equal(t, 0.8, device.Behavioral.AnomalyDetails["KARMA"])
	})

	t.Run("Evil Twin Detection", func(t *testing.T) {
		// Mock Registry to return "WPA2" for "CorporateWiFi"
		mockRegistry.On("GetSSIDSecurity", "CorporateWiFi").Return("WPA2", true)
		mockRegistry.On("GetAllDevices").Return([]domain.Device{
			{MAC: "VALID_MAC", SSID: "CorporateWiFi", Security: "WPA2", Type: "ap"},
		})

		device := domain.Device{
			MAC:        "EVIL_MAC",
			Type:       "ap",
			SSID:       "CorporateWiFi",
			Security:   "OPEN", // Mismatch
			Behavioral: &domain.BehavioralProfile{},
		}

		engine.Analyze(device)

		assert.Equal(t, 0.9, device.Behavioral.AnomalyDetails["EVIL_TWIN"])
	})
}
