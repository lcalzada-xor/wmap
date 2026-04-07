package storage

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestToModelAndDomain(t *testing.T) {
	now := time.Now().Truncate(time.Second) // Truncate to match DB precision usually

	domainDev := domain.Device{
		MAC:          "AA:BB:CC:DD:EE:FF",
		Type:         "station",
		Vendor:       "TestVendor",
		RSSI:         -50,
		SSID:         "TestSSID",
		IsRandomized: true,
		LastSeen:     now,
		ProbedSSIDs: map[string]time.Time{
			"Probe1": now,
		},
	}

	// 1. Domain -> Model
	model := toModel(domainDev)

	if model.MAC != domainDev.MAC {
		t.Errorf("Expected MAC %s, got %s", domainDev.MAC, model.MAC)
	}

	// 2. Model -> Domain
	// Mock probing relationship
	model.ProbedSSIDs = []ProbeModel{
		{DeviceMAC: model.MAC, SSID: "Probe1", LastSeen: now},
	}

	restored := toDomain(model)

	if restored.MAC != domainDev.MAC {
		t.Errorf("Restored MAC mismatch")
	}
	if ts, ok := restored.ProbedSSIDs["Probe1"]; !ok || !ts.Equal(now) {
		t.Errorf("Restored ProbedSSIDs mismatch")
	}
}
