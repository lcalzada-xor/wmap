package registry

import (
	"context"
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
	registry := NewDeviceRegistry(nil, nil)
	assert.NotNil(t, registry)
	assert.Equal(t, numShards, len(registry.shards))
	assert.NotNil(t, registry.ssidManager)
}

func TestDeviceRegistry_ProcessDevice_NewDevice(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)

	dev := domain.Device{
		MAC:            "AA:BB:CC:DD:EE:FF",
		RSSI:           -50,
		LastPacketTime: time.Now(),
		SSID:           "TestNetwork",
	}

	processed, isNew := registry.ProcessDevice(context.Background(), dev)

	assert.True(t, isNew, "Should be identified as a new device")
	assert.Equal(t, dev.MAC, processed.MAC)
	assert.Equal(t, "TestNetwork", processed.SSID)

	// Verify retrieval
	stored, found := registry.GetDevice(context.Background(), dev.MAC)
	assert.True(t, found)
	assert.Equal(t, dev.MAC, stored.MAC)
}

func TestDeviceRegistry_ProcessDevice_ExistingDevice_Merge(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)

	// timestamp 1
	t1 := time.Now().Add(-1 * time.Minute)
	dev1 := domain.Device{
		MAC:            "11:22:33:44:55:66",
		RSSI:           -80,
		LastPacketTime: t1,
		Vendor:         "OldVendor",
		Model:          "TestModel",
	}
	registry.ProcessDevice(context.Background(), dev1)

	// timestamp 2 (newer)
	t2 := time.Now()
	dev2 := domain.Device{
		MAC:            "11:22:33:44:55:66",
		RSSI:           -40, // better signal
		LastPacketTime: t2,
		Vendor:         "NewVendor", // Vendor update
		SSID:           "NewSSID",
	}

	processed, isNewDiscovery := registry.ProcessDevice(context.Background(), dev2)

	assert.False(t, isNewDiscovery, "Should not trigger new discovery if signature is same (empty)")
	assert.Equal(t, "NewVendor", processed.Vendor)
	assert.Equal(t, -40, processed.RSSI)
	assert.Equal(t, "NewSSID", processed.SSID)
	assert.True(t, processed.LastPacketTime.After(t1))
}

func TestDeviceRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)
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
			registry.ProcessDevice(context.Background(), dev)
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	stored, found := registry.GetDevice(context.Background(), mac)
	assert.True(t, found)
	// Check if PacketsCount accumulated correctly (DeviceRegistry merge logic adds counts)
	assert.Equal(t, 100, stored.PacketsCount)
}

func TestDeviceRegistry_PruneOldDevices(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)

	// Old device
	registry.ProcessDevice(context.Background(), domain.Device{
		MAC:            "OLD:OLD",
		LastPacketTime: time.Now().Add(-2 * time.Hour),
	})

	// New device
	registry.ProcessDevice(context.Background(), domain.Device{
		MAC:            "NEW:NEW",
		LastPacketTime: time.Now(),
	})

	deleted := registry.PruneOldDevices(context.Background(), 1*time.Hour)
	assert.Equal(t, 1, deleted)

	_, foundOld := registry.GetDevice(context.Background(), "OLD:OLD")
	assert.False(t, foundOld)

	_, foundNew := registry.GetDevice(context.Background(), "NEW:NEW")
	assert.True(t, foundNew)
}

func TestDeviceRegistry_ProcessDevice_MergeHandshake(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)
	mac := "00:AA:BB:CC:DD:EE"

	// 1. Packet WITHOUT handshake
	dev1 := domain.Device{
		MAC:          mac,
		HasHandshake: false,
	}
	registry.ProcessDevice(context.Background(), dev1)

	// 2. Packet WITH handshake
	dev2 := domain.Device{
		MAC:          mac,
		HasHandshake: true,
	}
	registry.ProcessDevice(context.Background(), dev2)

	stored, _ := registry.GetDevice(context.Background(), mac)
	assert.True(t, stored.HasHandshake, "Should set HasHandshake to true")

	// 3. Packet WITHOUT handshake (should not overwrite true with false)
	dev3 := domain.Device{
		MAC:          mac,
		HasHandshake: false,
	}
	registry.ProcessDevice(context.Background(), dev3)

	stored, _ = registry.GetDevice(context.Background(), mac)
	assert.True(t, stored.HasHandshake, "Should persist HasHandshake=true")
}
