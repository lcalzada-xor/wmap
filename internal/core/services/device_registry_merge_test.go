package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

// TestDeviceRegistry_MergeType verifies that Type field is properly merged
// with APs taking precedence over stations
func TestDeviceRegistry_MergeType(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	mac := "AA:BB:CC:DD:EE:FF"

	// Scenario 1: Station → AP (should update)
	t.Run("Station to AP upgrade", func(t *testing.T) {
		// First seen as station (probe request)
		dev1 := domain.Device{
			MAC:            mac,
			Type:           "station",
			LastPacketTime: time.Now(),
		}
		registry.ProcessDevice(dev1)

		stored, _ := registry.GetDevice(mac)
		assert.Equal(t, "station", stored.Type)

		// Later broadcasts beacon (is actually AP)
		dev2 := domain.Device{
			MAC:            mac,
			Type:           "ap",
			LastPacketTime: time.Now(),
		}
		registry.ProcessDevice(dev2)

		stored, _ = registry.GetDevice(mac)
		assert.Equal(t, "ap", stored.Type, "Should update station to AP")
	})

	// Scenario 2: AP → Station (should NOT downgrade)
	t.Run("AP should not downgrade to Station", func(t *testing.T) {
		mac2 := "11:22:33:44:55:66"

		// First seen as AP
		dev1 := domain.Device{
			MAC:            mac2,
			Type:           "ap",
			LastPacketTime: time.Now(),
		}
		registry.ProcessDevice(dev1)

		stored, _ := registry.GetDevice(mac2)
		assert.Equal(t, "ap", stored.Type)

		// Later sends probe request (acts as station)
		dev2 := domain.Device{
			MAC:            mac2,
			Type:           "station",
			LastPacketTime: time.Now(),
		}
		registry.ProcessDevice(dev2)

		stored, _ = registry.GetDevice(mac2)
		assert.Equal(t, "ap", stored.Type, "Should keep AP type, not downgrade to station")
	})

	// Scenario 3: Empty type should not overwrite existing
	t.Run("Empty type preserves existing", func(t *testing.T) {
		mac3 := "AA:AA:AA:AA:AA:AA"

		dev1 := domain.Device{
			MAC:            mac3,
			Type:           "station",
			LastPacketTime: time.Now(),
		}
		registry.ProcessDevice(dev1)

		// Update with no type specified
		dev2 := domain.Device{
			MAC:            mac3,
			Type:           "",
			LastPacketTime: time.Now(),
		}
		registry.ProcessDevice(dev2)

		stored, _ := registry.GetDevice(mac3)
		assert.Equal(t, "station", stored.Type, "Should preserve existing type when new type is empty")
	})
}

// TestDeviceRegistry_MergeChannel verifies that Channel field is properly updated
func TestDeviceRegistry_MergeChannel(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	mac := "BB:BB:BB:BB:BB:BB"

	// Initial device on channel 6
	dev1 := domain.Device{
		MAC:            mac,
		Channel:        6,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev1)

	stored, _ := registry.GetDevice(mac)
	assert.Equal(t, 6, stored.Channel)

	// Device moves to channel 11
	dev2 := domain.Device{
		MAC:            mac,
		Channel:        11,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev2)

	stored, _ = registry.GetDevice(mac)
	assert.Equal(t, 11, stored.Channel, "Should update to new channel")

	// Update with no channel (0) should not overwrite
	dev3 := domain.Device{
		MAC:            mac,
		Channel:        0,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev3)

	stored, _ = registry.GetDevice(mac)
	assert.Equal(t, 11, stored.Channel, "Should preserve channel when new channel is 0")
}

// TestDeviceRegistry_MergeProtocolFlags verifies that protocol capability flags
// are properly merged (once detected, always true)
func TestDeviceRegistry_MergeProtocolFlags(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	mac := "CC:CC:CC:CC:CC:CC"

	// First packet: no protocol flags
	dev1 := domain.Device{
		MAC:            mac,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev1)

	stored, _ := registry.GetDevice(mac)
	assert.False(t, stored.Has11k)
	assert.False(t, stored.Has11v)
	assert.False(t, stored.Has11r)

	// Second packet: 11k detected
	dev2 := domain.Device{
		MAC:            mac,
		Has11k:         true,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev2)

	stored, _ = registry.GetDevice(mac)
	assert.True(t, stored.Has11k, "Should set Has11k to true")
	assert.False(t, stored.Has11v)
	assert.False(t, stored.Has11r)

	// Third packet: 11v detected
	dev3 := domain.Device{
		MAC:            mac,
		Has11v:         true,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev3)

	stored, _ = registry.GetDevice(mac)
	assert.True(t, stored.Has11k, "Should persist Has11k")
	assert.True(t, stored.Has11v, "Should set Has11v to true")
	assert.False(t, stored.Has11r)

	// Fourth packet: 11r detected
	dev4 := domain.Device{
		MAC:            mac,
		Has11r:         true,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev4)

	stored, _ = registry.GetDevice(mac)
	assert.True(t, stored.Has11k, "Should persist Has11k")
	assert.True(t, stored.Has11v, "Should persist Has11v")
	assert.True(t, stored.Has11r, "Should set Has11r to true")

	// Fifth packet: no flags (should persist all)
	dev5 := domain.Device{
		MAC:            mac,
		Has11k:         false,
		Has11v:         false,
		Has11r:         false,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev5)

	stored, _ = registry.GetDevice(mac)
	assert.True(t, stored.Has11k, "Should persist Has11k even when new packet has false")
	assert.True(t, stored.Has11v, "Should persist Has11v even when new packet has false")
	assert.True(t, stored.Has11r, "Should persist Has11r even when new packet has false")
}

// TestDeviceRegistry_MergeAllNewFields tests all new merge fields together
func TestDeviceRegistry_MergeAllNewFields(t *testing.T) {
	registry := NewDeviceRegistry(nil)
	mac := "DD:DD:DD:DD:DD:DD"

	// Initial packet: station on channel 1
	dev1 := domain.Device{
		MAC:            mac,
		Type:           "station",
		Channel:        1,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev1)

	// Second packet: becomes AP on channel 6 with 11k
	dev2 := domain.Device{
		MAC:            mac,
		Type:           "ap",
		Channel:        6,
		Has11k:         true,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev2)

	stored, _ := registry.GetDevice(mac)
	assert.Equal(t, "ap", stored.Type, "Should upgrade to AP")
	assert.Equal(t, 6, stored.Channel, "Should update channel")
	assert.True(t, stored.Has11k, "Should detect 11k")

	// Third packet: adds 11v and 11r
	dev3 := domain.Device{
		MAC:            mac,
		Type:           "station", // Try to downgrade (should fail)
		Channel:        11,        // Change channel
		Has11v:         true,
		Has11r:         true,
		LastPacketTime: time.Now(),
	}
	registry.ProcessDevice(dev3)

	stored, _ = registry.GetDevice(mac)
	assert.Equal(t, "ap", stored.Type, "Should NOT downgrade from AP to station")
	assert.Equal(t, 11, stored.Channel, "Should update to new channel")
	assert.True(t, stored.Has11k, "Should persist 11k")
	assert.True(t, stored.Has11v, "Should detect 11v")
	assert.True(t, stored.Has11r, "Should detect 11r")
}
