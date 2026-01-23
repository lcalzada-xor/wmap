package security

import (
	"context"
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

func (m *MockRegistry) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	args := m.Called(ctx, ssid)
	return args.String(0), args.Bool(1)
}

// Implement other interface methods as stubs...
func (m *MockRegistry) ProcessDevice(ctx context.Context, device domain.Device) (domain.Device, bool) {
	return device, false
}
func (m *MockRegistry) LoadDevice(ctx context.Context, device domain.Device) {}
func (m *MockRegistry) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	return domain.Device{}, false
}
func (m *MockRegistry) GetAllDevices(ctx context.Context) []domain.Device {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Device)
}
func (m *MockRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int { return 0 }
func (m *MockRegistry) GetActiveCount(ctx context.Context) int                     { return 0 }
func (m *MockRegistry) UpdateSSID(ctx context.Context, ssid, security string)      {}
func (m *MockRegistry) GetSSIDs(ctx context.Context) map[string]bool               { return nil }
func (m *MockRegistry) Clear(ctx context.Context)                                  {}
func (m *MockRegistry) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	return 0
}

// TestIntelligenceFeatures verifies the new detection logic
func TestSecurityEngine_Intelligence(t *testing.T) {
	mockRegistry := new(MockRegistry)
	engine := NewSecurityEngine(mockRegistry)
	ctx := context.Background()

	t.Run("High Retry Rate Detection", func(t *testing.T) {
		device := domain.Device{
			MAC:          "00:11:22:33:44:55",
			PacketsCount: 100,
			RetryCount:   30, // 30% > 20% Threshold
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		assert.NotEmpty(t, alerts)

		found := false
		for _, alert := range alerts {
			if alert.Subtype == "HIGH_RETRY_RATE" && alert.DeviceMAC == "00:11:22:33:44:55" {
				found = true
				assert.Equal(t, domain.SeverityMedium, alert.Severity)
				break
			}
		}
		assert.True(t, found, "Expected HIGH_RETRY_RATE alert")
	})

	t.Run("Karma Detection", func(t *testing.T) {
		device := domain.Device{
			MAC:  "AA:BB:CC:DD:EE:FF",
			Type: "station", // Existing detector logic checks for ProbedSSIDs (Client behavior)
			ProbedSSIDs: map[string]time.Time{
				"Home": time.Now(), "Guest": time.Now(), "Starbucks": time.Now(),
				"FreeWifi": time.Now(), "Airport": time.Now(), "Hotel": time.Now(), // > 5
			},
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		found := false
		for _, alert := range alerts {
			if alert.Subtype == "KARMA_DETECTION" && alert.DeviceMAC == "AA:BB:CC:DD:EE:FF" {
				found = true
				assert.Equal(t, domain.SeverityHigh, alert.Severity)
				break
			}
		}
		assert.True(t, found, "Expected KARMA_DETECTION alert")
	})

	t.Run("AP Karma Detection (Mana)", func(t *testing.T) {
		device := domain.Device{
			MAC:           "11:22:33:44:55:66",
			Type:          "ap",
			ObservedSSIDs: []string{"FreeWiFi", "Corporate"},
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		found := false
		for _, alert := range alerts {
			if alert.Subtype == "KARMA_AP_DETECTED" && alert.DeviceMAC == "11:22:33:44:55:66" {
				found = true
				assert.Equal(t, domain.SeverityCritical, alert.Severity)
				assert.Contains(t, alert.Details, "broadcasting 2 distinct SSIDs")
				break
			}
		}
		assert.True(t, found, "Expected KARMA_AP_DETECTED alert")
	})

	t.Run("Evil Twin Detection", func(t *testing.T) {
		// Mock Registry to return "WPA2" for "CorporateWiFi"
		mockRegistry.On("GetSSIDSecurity", ctx, "CorporateWiFi").Return("WPA2", true)

		device := domain.Device{
			MAC:      "EVIL_MAC",
			Type:     "ap",
			SSID:     "CorporateWiFi",
			Security: "OPEN", // Mismatch
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		found := false
		for _, alert := range alerts {
			if alert.Subtype == "EVIL_TWIN_DETECTED" && alert.DeviceMAC == "EVIL_MAC" {
				found = true
				assert.Equal(t, domain.SeverityCritical, alert.Severity)
				break
			}
		}
		assert.True(t, found, "Expected EVIL_TWIN_DETECTED alert")
	})
}
