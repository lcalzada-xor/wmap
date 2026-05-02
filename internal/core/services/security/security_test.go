package security

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

func TestSecurityIntelligenceAlerts(t *testing.T) {
	// Directly use SecurityEngine
	mockReg := &MockRegistrySecurity{
		ssidSecurity: map[string]string{
			"EvilTwinTest": "WPA2",
		},
	}
	svc := NewSecurityEngine(mockReg)

	// 1. High Retry Rate Detection — >=200 packets, >40% rate, good signal
	macRetry := "AA:AA:AA:AA:AA:AA"
	svc.Analyze(context.Background(), domain.Device{
		MAC:            macRetry,
		PacketsCount:   200,
		RetryCount:     90, // 45% > 40%
		RSSI:           -50,
		LastPacketTime: time.Now(),
	})

	// 2. Karma / Honeypot Detection — >=20 total probes, >=5 recent
	apMAC := "BB:BB:BB:BB:BB:BB"
	probes := make(map[string]time.Time)
	old := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 15; i++ {
		probes[string(rune('A'+i))] = old
	}
	for i := 0; i < 5; i++ {
		probes[string(rune('P'+i))] = time.Now()
	}
	svc.Analyze(context.Background(), domain.Device{
		MAC:            apMAC,
		Type:           "station",
		ProbedSSIDs:    probes,
		LastPacketTime: time.Now(),
	})

	// 3. Evil Twin Detection (Placeholder in logic, but test case exists)
	ssid := "EvilTwinTest"
	svc.Analyze(context.Background(), domain.Device{
		MAC:            "CC:CC:CC:CC:CC:CC",
		Type:           "ap",
		SSID:           ssid,
		Security:       "WPA2",
		LastPacketTime: time.Now(),
	})
	// Same SSID, different MAC, different security
	svc.Analyze(context.Background(), domain.Device{
		MAC:            "DD:DD:DD:DD:DD:DD",
		Type:           "ap",
		SSID:           ssid,
		Security:       "OPEN",
		LastPacketTime: time.Now().Add(time.Second),
	})

	alerts := svc.GetAlerts(context.Background())

	hasRetry := false
	hasKarma := false
	hasEvilTwin := false

	for _, a := range alerts {
		switch a.Subtype {
		case "HIGH_RETRY_RATE":
			if a.DeviceMAC == macRetry {
				hasRetry = true
			}
		case "KARMA_DETECTION":
			if a.DeviceMAC == apMAC {
				hasKarma = true
			}
		case "EVIL_TWIN_DETECTED":
			if a.DeviceMAC == "DD:DD:DD:DD:DD:DD" {
				hasEvilTwin = true
			}
		}
	}

	if !hasRetry {
		t.Error("High Retry Rate alert not triggered")
	}
	if !hasKarma {
		t.Error("Karma Detection alert not triggered")
	}
	if !hasEvilTwin {
		t.Error("Evil Twin alert not triggered")
	}
}

func TestSecurityEngine_evaluateRules(t *testing.T) {
	// Directly setup SecurityEngine with mock registry
	mockReg := &MockRegistrySecurity{}
	svc := NewSecurityEngine(mockReg)

	// Add Rules
	ruleSSID := domain.AlertRule{
		ID:      "rule-1",
		Enabled: true,
		Type:    domain.AlertSSID,
		Value:   "TargetCorp",
		Exact:   false, // Contains
	}
	svc.AddRule(context.Background(), ruleSSID)

	ruleMAC := domain.AlertRule{
		ID:      "rule-2",
		Enabled: true,
		Type:    domain.AlertMAC,
		Value:   "11:22:33:44:55:66",
	}
	svc.AddRule(context.Background(), ruleMAC)

	// 1. Trigger SSID Rule
	svc.Analyze(context.Background(), domain.Device{
		MAC:  "aa:bb:cc:dd:ee:ff",
		SSID: "TargetCorp_Guest",
	})

	// 2. Trigger MAC Rule
	svc.Analyze(context.Background(), domain.Device{
		MAC:  "11:22:33:44:55:66",
		SSID: "HomeWifi",
	})

	alerts := svc.GetAlerts(context.Background())
	foundSSID := false
	foundMAC := false

	for _, a := range alerts {
		if a.RuleID == "rule-1" {
			foundSSID = true
		}
		if a.RuleID == "rule-2" {
			foundMAC = true
		}
	}

	if !foundSSID {
		t.Error("SSID Rule not triggered")
	}
	if !foundMAC {
		t.Error("MAC Rule not triggered")
	}
}

// MockRegistrySecurity specific for this test
type MockRegistrySecurity struct {
	ports.DeviceRegistry
	ssidSecurity map[string]string
}

func (m *MockRegistrySecurity) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	if m.ssidSecurity == nil {
		return "", false
	}
	sec, ok := m.ssidSecurity[ssid]
	return sec, ok
}
func (m *MockRegistrySecurity) GetAllDevices(ctx context.Context) []domain.Device {
	return []domain.Device{}
}
func (m *MockRegistrySecurity) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	return domain.Device{}, false
}
