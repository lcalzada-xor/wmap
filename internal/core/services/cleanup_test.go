package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestDeviceRegistry_CleanupStaleConnections(t *testing.T) {
	registry := NewDeviceRegistry(nil)

	// Setup: 3 Devices
	// 1. Active Connected (Just seen)
	// 2. Stale Connected (Seen > 2 mins ago)
	// 3. Stale Disconnected (Seen > 2 mins ago, but already disconnected)

	now := time.Now()
	staleTime := now.Add(-3 * time.Minute)

	devActive := domain.Device{
		MAC:              "11:11:11:11:11:11",
		ConnectionState:  domain.StateConnected,
		LastPacketTime:   now,
		ConnectedSSID:    "WiFi_1",
		ConnectionTarget: "AA:AA:AA:AA:AA:AA",
	}

	devStale := domain.Device{
		MAC:              "22:22:22:22:22:22",
		ConnectionState:  domain.StateConnected,
		LastPacketTime:   staleTime,
		ConnectedSSID:    "WiFi_2",
		ConnectionTarget: "BB:BB:BB:BB:BB:BB",
	}

	devAlreadyDisc := domain.Device{
		MAC:             "33:33:33:33:33:33",
		ConnectionState: domain.StateDisconnected,
		LastPacketTime:  staleTime,
		ConnectedSSID:   "",
	}

	registry.ProcessDevice(devActive)
	registry.ProcessDevice(devStale)
	registry.ProcessDevice(devAlreadyDisc)

	// Run Cleanup with 2 minute timeout
	count := registry.CleanupStaleConnections(2 * time.Minute)

	// Assertions
	assert.Equal(t, 1, count, "Should cleanup exactly 1 device")

	// Verify States
	d1, _ := registry.GetDevice(devActive.MAC)
	assert.Equal(t, domain.StateConnected, d1.ConnectionState)
	assert.Equal(t, "AA:AA:AA:AA:AA:AA", d1.ConnectionTarget)

	d2, _ := registry.GetDevice(devStale.MAC)
	assert.Equal(t, domain.StateDisconnected, d2.ConnectionState)
	assert.Equal(t, "", d2.ConnectedSSID) // Should be cleared
	assert.Equal(t, "", d2.ConnectionTarget)

	d3, _ := registry.GetDevice(devAlreadyDisc.MAC)
	assert.Equal(t, domain.StateDisconnected, d3.ConnectionState)
}
