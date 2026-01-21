package storage

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupInMemoryDB creates a new SQLiteAdapter used for testing
func setupInMemoryDB(t *testing.T) *SQLiteAdapter {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&DeviceModel{}, &ProbeModel{}, &VulnerabilityModel{})
	require.NoError(t, err)

	return &SQLiteAdapter{db: db}
}

func TestSaveAndGetDevice(t *testing.T) {
	adapter := setupInMemoryDB(t)

	dev := domain.Device{
		MAC:            "AA:BB:CC:DD:EE:FF",
		Type:           "station",
		Vendor:         "TestVendor",
		RSSI:           -60,
		LastPacketTime: time.Now(),
		SSID:           "TestSSID",
	}

	err := adapter.SaveDevice(context.Background(), dev)
	assert.NoError(t, err)

	stored, err := adapter.GetDevice(context.Background(), dev.MAC)
	assert.NoError(t, err)
	assert.NotNil(t, stored)
	assert.Equal(t, dev.MAC, stored.MAC)
	assert.Equal(t, dev.Vendor, stored.Vendor)
}

func TestSaveDevice_Update(t *testing.T) {
	adapter := setupInMemoryDB(t)

	// Save initial
	dev := domain.Device{MAC: "00:00:00:00:00:01", RSSI: -80, Vendor: "Old"}
	adapter.SaveDevice(context.Background(), dev)

	// Update
	dev.RSSI = -50
	dev.Vendor = "New"
	adapter.SaveDevice(context.Background(), dev)

	stored, _ := adapter.GetDevice(context.Background(), dev.MAC)
	assert.Equal(t, -50, stored.RSSI)
	assert.Equal(t, "New", stored.Vendor)
}

func TestGetDevicesByFilter(t *testing.T) {
	adapter := setupInMemoryDB(t)

	// Seed Data
	d1 := domain.Device{MAC: "11:11:11:11:11:11", Type: "station", RSSI: -40, Vendor: "Apple"}
	d2 := domain.Device{MAC: "22:22:22:22:22:22", Type: "ap", RSSI: -90, Vendor: "Cisco"}
	d3 := domain.Device{MAC: "33:33:33:33:33:33", Type: "station", RSSI: -50, Vendor: "Apple"}

	adapter.SaveDevice(context.Background(), d1)
	adapter.SaveDevice(context.Background(), d2)
	adapter.SaveDevice(context.Background(), d3)

	// Test 1: Filter by RSSI
	f1 := domain.DeviceFilter{MinRSSI: -60}
	res1, err := adapter.GetDevicesByFilter(context.Background(), f1)
	assert.NoError(t, err)
	assert.Len(t, res1, 2) // d1 and d3

	// Test 2: Filter by Vendor
	f2 := domain.DeviceFilter{Vendor: "Apple"}
	res2, err := adapter.GetDevicesByFilter(context.Background(), f2)
	assert.NoError(t, err)
	assert.Len(t, res2, 2)

	// Test 3: Filter by Type
	f3 := domain.DeviceFilter{Type: "ap"}
	res3, err := adapter.GetDevicesByFilter(context.Background(), f3)
	assert.NoError(t, err)
	assert.Len(t, res3, 1)
	assert.Equal(t, "Cisco", res3[0].Vendor)
}

func TestProbedSSIDs_Persistence(t *testing.T) {
	adapter := setupInMemoryDB(t)

	probes := map[string]time.Time{
		"HomeWiFi":   time.Now(),
		"OfficeWiFi": time.Now(),
	}

	dev := domain.Device{
		MAC:         "AA:AA:AA:AA:AA:AA",
		ProbedSSIDs: probes,
	}

	err := adapter.SaveDevice(context.Background(), dev)
	assert.NoError(t, err)

	stored, err := adapter.GetDevice(context.Background(), dev.MAC)
	assert.NoError(t, err)
	assert.Len(t, stored.ProbedSSIDs, 2)
	_, exists := stored.ProbedSSIDs["HomeWiFi"]
	assert.True(t, exists)
}

func TestVulnerability_Persistence(t *testing.T) {
	adapter := setupInMemoryDB(t)

	record := domain.VulnerabilityRecord{
		ID:        "vuln-1",
		DeviceMAC: "AA:BB:CC:DD:EE:FF",
		Name:      "Weak Ciphers",
		Status:    domain.VulnStatusActive,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	// Save
	err := adapter.SaveVulnerability(context.Background(), record)
	assert.NoError(t, err)

	// Retrieve
	stored, err := adapter.GetVulnerability(context.Background(), "vuln-1")
	assert.NoError(t, err)
	assert.Equal(t, "Weak Ciphers", stored.Name)

	// Update Status with Notes
	err = adapter.UpdateVulnerabilityStatus(context.Background(), "vuln-1", domain.VulnStatusIgnored, "False positive test")
	assert.NoError(t, err)

	// Verify Update
	stored2, err := adapter.GetVulnerability(context.Background(), "vuln-1")
	assert.NoError(t, err)
	assert.Equal(t, domain.VulnStatusIgnored, stored2.Status)
	assert.Equal(t, "False positive test", stored2.Notes)
	assert.False(t, stored2.StatusChangedAt.IsZero(), "StatusChangedAt should be set")
}
