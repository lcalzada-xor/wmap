package registry

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSignatureMatcher for testing discovery
type MockSignatureMatcher struct {
	mock.Mock
}

func (m *MockSignatureMatcher) MatchSignature(d domain.Device) *domain.SignatureMatch {
	args := m.Called(d)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*domain.SignatureMatch)
}

func (m *MockSignatureMatcher) ReloadSignatures() error {
	return nil
}

func TestNewDeviceRegistry(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	assert.NotNil(t, registry)
	assert.Equal(t, numShards, len(registry.shards))
	assert.NotNil(t, registry.ssids)
}

func TestDeviceRegistry_ProcessDevice_NewDevice(t *testing.T) {
	registry := NewDeviceRegistry(nil)

	dev := domain.Device{
		MAC:            "AA:BB:CC:DD:EE:FF",
		RSSI:           -50,
		LastPacketTime: time.Now(),
		SSID:           "TestNetwork",
	}

	processed, isNew := registry.ProcessDevice(dev)

	assert.True(t, isNew, "Should be identified as a new device")
	assert.Equal(t, dev.MAC, processed.MAC)
	assert.Equal(t, "TestNetwork", processed.SSID)

	// Verify retrieval
	stored, found := registry.GetDevice(dev.MAC)
	assert.True(t, found)
	assert.Equal(t, dev.MAC, stored.MAC)
}

func TestDeviceRegistry_ProcessDevice_ExistingDevice_Merge(t *testing.T) {
	registry := NewDeviceRegistry(nil)

	// timestamp 1
	t1 := time.Now().Add(-1 * time.Minute)
	dev1 := domain.Device{
		MAC:            "11:22:33:44:55:66",
		RSSI:           -80,
		LastPacketTime: t1,
		Vendor:         "OldVendor",
		Model:          "TestModel",
	}
	registry.ProcessDevice(dev1)

	// timestamp 2 (newer)
	t2 := time.Now()
	dev2 := domain.Device{
		MAC:            "11:22:33:44:55:66",
		RSSI:           -40, // better signal
		LastPacketTime: t2,
		Vendor:         "NewVendor", // Vendor update
		SSID:           "NewSSID",
	}

	processed, isNewDiscovery := registry.ProcessDevice(dev2)

	assert.False(t, isNewDiscovery, "Should not trigger new discovery if signature is same (empty)")
	assert.Equal(t, "NewVendor", processed.Vendor)
	assert.Equal(t, -40, processed.RSSI)
	assert.Equal(t, "NewSSID", processed.SSID)
	assert.True(t, processed.LastPacketTime.After(t1))
}

func TestDeviceRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	mac := "00:11:22:33:44:55"

	// Create 100 goroutines trying to update the same device
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			dev := domain.Device{
				MAC:            mac,
				LastPacketTime: time.Now(),
				PacketsCount:   1,
			}
			registry.ProcessDevice(dev)
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	stored, found := registry.GetDevice(mac)
	assert.True(t, found)
	// Check if PacketsCount accumulated correctly (DeviceRegistry merge logic adds counts)
	assert.Equal(t, 100, stored.PacketsCount)
}

func TestDeviceRegistry_PruneOldDevices(t *testing.T) {
	registry := NewDeviceRegistry(nil)

	// Old device
	registry.ProcessDevice(domain.Device{
		MAC:            "OLD:OLD",
		LastPacketTime: time.Now().Add(-2 * time.Hour),
	})

	// New device
	registry.ProcessDevice(domain.Device{
		MAC:            "NEW:NEW",
		LastPacketTime: time.Now(),
	})

	deleted := registry.PruneOldDevices(1 * time.Hour)
	assert.Equal(t, 1, deleted)

	_, foundOld := registry.GetDevice("OLD:OLD")
	assert.False(t, foundOld)

	_, foundNew := registry.GetDevice("NEW:NEW")
	assert.True(t, foundNew)
}

func TestDeviceRegistry_ProcessDevice_MergeHandshake(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	mac := "00:AA:BB:CC:DD:EE"

	// 1. Packet WITHOUT handshake
	dev1 := domain.Device{
		MAC:          mac,
		HasHandshake: false,
	}
	registry.ProcessDevice(dev1)

	// 2. Packet WITH handshake
	dev2 := domain.Device{
		MAC:          mac,
		HasHandshake: true,
	}
	registry.ProcessDevice(dev2)

	stored, _ := registry.GetDevice(mac)
	assert.True(t, stored.HasHandshake, "Should set HasHandshake to true")

	// 3. Packet WITHOUT handshake (should not overwrite true with false)
	dev3 := domain.Device{
		MAC:          mac,
		HasHandshake: false,
	}
	registry.ProcessDevice(dev3)

	stored, _ = registry.GetDevice(mac)
	assert.True(t, stored.HasHandshake, "Should persist HasHandshake=true")
}
