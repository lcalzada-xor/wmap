package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRegistry for Intelligence tests
type MockRegistry struct {
	mock.Mock
}

// Implement necessary interface methods stub
func (m *MockRegistry) ProcessDevice(ctx context.Context, device domain.Device) (domain.Device, bool) {
	return device, false
}
func (m *MockRegistry) LoadDevice(ctx context.Context, device domain.Device) {}
func (m *MockRegistry) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	return domain.Device{}, false
}
func (m *MockRegistry) GetAllDevices(ctx context.Context) []domain.Device          { return nil }
func (m *MockRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int { return 0 }
func (m *MockRegistry) GetActiveCount(ctx context.Context) int                     { return 0 }
func (m *MockRegistry) UpdateSSID(ctx context.Context, ssid, security string)      {}
func (m *MockRegistry) GetSSIDs(ctx context.Context) map[string]bool               { return nil }
func (m *MockRegistry) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	return "", false
}
func (m *MockRegistry) Clear(ctx context.Context) {}
func (m *MockRegistry) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	return 0
}

func TestSecurity_AdvancedKarmaDetection(t *testing.T) {
	mockRegistry := new(MockRegistry)
	engine := security.NewSecurityEngine(mockRegistry)
	ctx := context.Background()

	t.Run("APKarmaDetector_NoAlertForSingleSSID", func(t *testing.T) {
		device := domain.Device{
			MAC:           "00:00:00:11:11:11",
			Type:          "ap",
			ObservedSSIDs: []string{"JustOne"},
		}

		engine.Analyze(ctx, device)

		alerts := engine.GetAlerts(ctx)
		// Should NOT find KARMA_AP_DETECTED for this MAC
		found := false
		for _, a := range alerts {
			if a.DeviceMAC == device.MAC && a.Subtype == "KARMA_AP_DETECTED" {
				found = true
			}
		}
		assert.False(t, found)
	})

	t.Run("APKarmaDetector_AlertForMultipleSSIDs", func(t *testing.T) {
		device := domain.Device{
			MAC:           "00:00:00:22:22:22",
			Type:          "ap",
			ObservedSSIDs: []string{"FreeWiFi", "Office", "Starbucks"},
		}

		engine.Analyze(ctx, device)

		alerts := engine.GetAlerts(ctx)
		found := false
		for _, a := range alerts {
			if a.DeviceMAC == device.MAC && a.Subtype == "KARMA_AP_DETECTED" {
				found = true
				assert.Equal(t, domain.SeverityCritical, a.Severity)
			}
		}
		assert.True(t, found)
	})

	t.Run("ClientKarmaDetector_AlertForExcessiveProbes", func(t *testing.T) {
		device := domain.Device{
			MAC:         "00:00:00:33:33:33",
			Type:        "station",
			ProbedSSIDs: make(map[string]time.Time),
		}

		// Add 6 probes (Threshold is 5)
		ssids := []string{"A", "B", "C", "D", "E", "F"}
		for _, s := range ssids {
			device.ProbedSSIDs[s] = time.Now()
		}

		engine.Analyze(ctx, device)

		alerts := engine.GetAlerts(ctx)
		found := false
		for _, a := range alerts {
			if a.DeviceMAC == device.MAC && a.Subtype == "KARMA_DETECTION" {
				found = true
			}
		}
		assert.True(t, found)
	})
}
