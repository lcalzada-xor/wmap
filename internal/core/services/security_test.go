package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
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
