package storage

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestToModelAndDomain(t *testing.T) {
	now := time.Now().Truncate(time.Second) // Truncate to match DB precision usually
	activeHours := []int{10, 11, 12}

	domainDev := domain.Device{
		MAC:          "AA:BB:CC:DD:EE:FF",
		Type:         "station",
		Vendor:       "TestVendor",
		RSSI:         -50,
		SSID:         "TestSSID",
		IsRandomized: true,
		LastSeen:     now,
		Behavioral: &domain.BehavioralProfile{
			MAC:          "AA:BB:CC:DD:EE:FF",
			AnomalyScore: 0.5,
			ActiveHours:  activeHours,
		},
		ProbedSSIDs: map[string]time.Time{
			"Probe1": now,
		},
	}

	// 1. Domain -> Model
	model := toModel(domainDev)

	if model.MAC != domainDev.MAC {
		t.Errorf("Expected MAC %s, got %s", domainDev.MAC, model.MAC)
	}
	if model.AnomalyScore != 0.5 {
		t.Errorf("Expected AnomalyScore 0.5, got %f", model.AnomalyScore)
	}

	var storedHours []int
	_ = json.Unmarshal([]byte(model.ActiveHours), &storedHours)
	if !reflect.DeepEqual(storedHours, activeHours) {
		t.Errorf("Expected ActiveHours %v, got %v", activeHours, storedHours)
	}

	// 2. Model -> Domain
	// Mock probing relationship
	model.ProbedSSIDs = []ProbeModel{
		{SSID: "Probe1", LastSeen: now},
	}

	restored := toDomain(model)

	if restored.MAC != domainDev.MAC {
		t.Errorf("Restored MAC mismatch")
	}
	if restoreHours := restored.Behavioral.ActiveHours; !reflect.DeepEqual(restoreHours, activeHours) {
		t.Errorf("Restored ActiveHours mismatch: %v", restoreHours)
	}
	if ts, ok := restored.ProbedSSIDs["Probe1"]; !ok || !ts.Equal(now) {
		t.Errorf("Restored ProbedSSIDs mismatch")
	}
}
