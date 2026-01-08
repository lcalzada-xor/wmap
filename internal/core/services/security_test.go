package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

func TestSecurityIntelligenceAlerts(t *testing.T) {
	svc := setupTestService()

	// 1. High Retry Rate Detection
	macRetry := "AA:AA:AA:AA:AA:AA"
	svc.ProcessDevice(domain.Device{
		MAC:            macRetry,
		PacketsCount:   30,
		RetryCount:     20, // 66%
		LastPacketTime: time.Now(),
	})

	// 2. Karma / Honeypot Detection
	apMAC := "BB:BB:BB:BB:BB:BB"
	probes := make(map[string]time.Time)
	for i := 0; i < 7; i++ {
		probes[string(rune('A'+i))] = time.Now()
	}
	svc.ProcessDevice(domain.Device{
		MAC:            apMAC,
		Type:           "ap",
		ProbedSSIDs:    probes,
		LastPacketTime: time.Now(),
	})

	// 3. Evil Twin Detection
	ssid := "EvilTwinTest"
	svc.ProcessDevice(domain.Device{
		MAC:            "CC:CC:CC:CC:CC:CC",
		Type:           "ap",
		SSID:           ssid,
		Security:       "WPA2",
		LastPacketTime: time.Now(),
	})
	// Same SSID, different MAC, different security
	svc.ProcessDevice(domain.Device{
		MAC:            "DD:DD:DD:DD:DD:DD",
		Type:           "ap",
		SSID:           ssid,
		Security:       "OPEN",
		LastPacketTime: time.Now().Add(time.Second),
	})

	alerts := svc.GetAlerts()

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
	svc.AddRule(ruleSSID)

	ruleMAC := domain.AlertRule{
		ID:      "rule-2",
		Enabled: true,
		Type:    domain.AlertMAC,
		Value:   "11:22:33:44:55:66",
	}
	svc.AddRule(ruleMAC)

	// 1. Trigger SSID Rule
	svc.Analyze(domain.Device{
		MAC:        "aa:bb:cc:dd:ee:ff",
		SSID:       "TargetCorp_Guest",
		Behavioral: &domain.BehavioralProfile{AnomalyDetails: make(map[string]float64)},
	})

	// 2. Trigger MAC Rule
	svc.Analyze(domain.Device{
		MAC:        "11:22:33:44:55:66",
		SSID:       "HomeWifi",
		Behavioral: &domain.BehavioralProfile{AnomalyDetails: make(map[string]float64)},
	})

	alerts := svc.GetAlerts()
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
}

func (m *MockRegistrySecurity) GetSSIDSecurity(ssid string) (string, bool) { return "", false }
func (m *MockRegistrySecurity) GetAllDevices() []domain.Device             { return []domain.Device{} }
func (m *MockRegistrySecurity) GetDevice(mac string) (domain.Device, bool) {
	return domain.Device{}, false
}

// Redefining helpers if missing, or we can just assume they exist if compilation passes.
// But to be safe, if setupTestService is already defined in another file, we shouldn't redefine it.
// We are in 'services' package.
// If previous test run passed existing security tests, setupTestService must be there.
// I will NOT redefine it.
