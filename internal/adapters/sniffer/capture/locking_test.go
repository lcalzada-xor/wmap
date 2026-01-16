package capture

import (
	"context"
	"testing"

	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/hopping"
	"github.com/stretchr/testify/assert"
)

func TestSniffer_Locking_ReferenceCounting(t *testing.T) {
	// Mock channel setter
	originalSetter := *SetChannelSetter
	defer func() { *SetChannelSetter = originalSetter }()
	*SetChannelSetter = func(iface string, channel int) error {
		return nil // Success
	}

	// Setup barebones sniffer
	s := &Sniffer{
		Config: SnifferConfig{
			Interface: "wlan0",
			Channels:  []int{1, 6, 11},
			DwellTime: 100,
		},
	}
	// Init hopper
	s.Hopper = hopping.NewHopper("wlan0", []int{1, 6, 11}, 100*time.Millisecond, nil)

	// 1. Initial State
	assert.Equal(t, 0, s.lockCount)
	assert.False(t, s.hopperPaused)

	// 2. First Lock (Channel 6)
	err := s.Lock("wlan0", 6)
	assert.NoError(t, err)
	assert.Equal(t, 1, s.lockCount)
	assert.Equal(t, 6, s.lockChannel)
	assert.True(t, s.hopperPaused, "Hopper should be paused")

	// 3. Second Lock (Same Channel) - Ref Count Increment
	err = s.Lock("wlan0", 6)
	assert.NoError(t, err)
	assert.Equal(t, 2, s.lockCount, "Ref count should increment")

	// 4. Conflicting Lock (Channel 1) - Error
	err = s.Lock("wlan0", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "busy")
	assert.Equal(t, 2, s.lockCount, "Ref count should remain unchanged after error")

	// 5. Unlock (Decrement)
	err = s.Unlock("wlan0")
	assert.NoError(t, err)
	assert.Equal(t, 1, s.lockCount)
	assert.True(t, s.hopperPaused, "Hopper should still be paused")

	// 6. Last Unlock (Resume)
	err = s.Unlock("wlan0")
	assert.NoError(t, err)
	assert.Equal(t, 0, s.lockCount)
	assert.False(t, s.hopperPaused, "Hopper should resume")
	assert.Equal(t, 0, s.lockChannel)
}

func TestSniffer_ExecuteWithLock(t *testing.T) {
	// Mock channel setter
	originalSetter := *SetChannelSetter
	defer func() { *SetChannelSetter = originalSetter }()
	*SetChannelSetter = func(iface string, channel int) error {
		return nil // Success
	}

	s := &Sniffer{
		Config: SnifferConfig{Interface: "wlan0", Channels: []int{1}},
	}

	ctx := context.Background()
	executed := false

	err := s.ExecuteWithLock(ctx, "wlan0", 6, func() error {
		executed = true
		assert.Equal(t, 1, s.lockCount)
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, executed)
	assert.Equal(t, 0, s.lockCount)
}
