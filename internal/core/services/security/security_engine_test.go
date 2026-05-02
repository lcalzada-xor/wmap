package security

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
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
func (m *MockRegistry) AddObserver(observer ports.DeviceObserver) {}


// TestIntelligenceFeatures verifies the new detection logic
func TestSecurityEngine_Intelligence(t *testing.T) {
	mockRegistry := new(MockRegistry)
	engine := NewSecurityEngine(mockRegistry)
	ctx := context.Background()

	t.Run("High Retry Rate Detection", func(t *testing.T) {
		device := domain.Device{
			MAC:          "00:11:22:33:44:55",
			PacketsCount: 200,
			RetryCount:   90, // 45% > 40% threshold, meets >=200 packet minimum
			RSSI:         -50, // Good signal — not a weak-signal FP
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		assert.NotEmpty(t, alerts)

		found := false
		for _, alert := range alerts {
			if alert.Subtype == "HIGH_RETRY_RATE" && alert.DeviceMAC == "00:11:22:33:44:55" {
				found = true
				assert.Equal(t, "Medium", alert.Severity)
				break
			}
		}
		assert.True(t, found, "Expected HIGH_RETRY_RATE alert")
	})

	t.Run("High Retry Rate suppressed for weak signal", func(t *testing.T) {
		device := domain.Device{
			MAC:          "00:11:22:33:44:AA",
			PacketsCount: 200,
			RetryCount:   90, // 45% — would fire, but RSSI is weak
			RSSI:         -80,
		}
		engine.Analyze(context.Background(), device)
		alerts := engine.GetAlerts(context.Background())
		for _, alert := range alerts {
			if alert.Subtype == "HIGH_RETRY_RATE" && alert.DeviceMAC == "00:11:22:33:44:AA" {
				t.Error("Should NOT alert for high retries at weak signal")
			}
		}
	})

	t.Run("Karma Detection", func(t *testing.T) {
		// 20 total probes with 5 recent ones — meets both thresholds
		now := time.Now()
		old := now.Add(-10 * time.Minute)
		probes := make(map[string]time.Time)
		for i := 0; i < 15; i++ {
			probes[fmt.Sprintf("OldNet%d", i)] = old
		}
		for i := 0; i < 5; i++ {
			probes[fmt.Sprintf("RecentNet%d", i)] = now
		}
		device := domain.Device{
			MAC:         "AA:BB:CC:DD:EE:FF",
			Type:        "station",
			ProbedSSIDs: probes,
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		found := false
		for _, alert := range alerts {
			if alert.Subtype == "KARMA_DETECTION" && alert.DeviceMAC == "AA:BB:CC:DD:EE:FF" {
				found = true
				assert.Equal(t, "High", alert.Severity)
				break
			}
		}
		assert.True(t, found, "Expected KARMA_DETECTION alert")
	})

	t.Run("Karma Detection suppressed for stale history only", func(t *testing.T) {
		old := time.Now().Add(-10 * time.Minute)
		probes := make(map[string]time.Time)
		for i := 0; i < 20; i++ {
			probes[fmt.Sprintf("OldNet%d", i)] = old
		}
		device := domain.Device{
			MAC:         "AA:BB:CC:DD:EE:00",
			Type:        "station",
			ProbedSSIDs: probes,
		}
		engine.Analyze(context.Background(), device)
		alerts := engine.GetAlerts(context.Background())
		for _, alert := range alerts {
			if alert.Subtype == "KARMA_DETECTION" && alert.DeviceMAC == "AA:BB:CC:DD:EE:00" {
				t.Error("Should NOT alert when all probes are stale")
			}
		}
	})

	t.Run("AP Karma Detection (Mana)", func(t *testing.T) {
		// 4 distinct SSIDs meets the new threshold (2 was too low — normal for home routers)
		device := domain.Device{
			MAC:           "11:22:33:44:55:66",
			Type:          "ap",
			ObservedSSIDs: []string{"FreeWiFi", "Corporate", "Guest", "Hidden"},
		}

		engine.Analyze(context.Background(), device)

		alerts := engine.GetAlerts(context.Background())
		found := false
		for _, alert := range alerts {
			if alert.Subtype == "KARMA_AP_DETECTED" && alert.DeviceMAC == "11:22:33:44:55:66" {
				found = true
				assert.Equal(t, "Critical", alert.Severity)
				assert.Contains(t, alert.Details, "4 distinct SSIDs")
				break
			}
		}
		assert.True(t, found, "Expected KARMA_AP_DETECTED alert")
	})

	t.Run("AP Karma Detection suppressed below threshold", func(t *testing.T) {
		// 2 SSIDs is normal for any AP with a guest network — should NOT fire
		device := domain.Device{
			MAC:           "11:22:33:44:55:77",
			Type:          "ap",
			ObservedSSIDs: []string{"Home", "HomeGuest"},
		}
		engine.Analyze(context.Background(), device)
		alerts := engine.GetAlerts(context.Background())
		for _, alert := range alerts {
			if alert.Subtype == "KARMA_AP_DETECTED" && alert.DeviceMAC == "11:22:33:44:55:77" {
				t.Error("Should NOT alert for AP with only 2 SSIDs (normal VAP setup)")
			}
		}
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
				assert.Equal(t, "Critical", alert.Severity)
				break
			}
		}
		assert.True(t, found, "Expected EVIL_TWIN_DETECTED alert")
	})
}
