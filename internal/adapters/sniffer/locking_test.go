package sniffer

import (
	"context"
	"testing"

	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/hopping"
	"github.com/stretchr/testify/assert"
)

type MockSwitcher struct{}

func (m *MockSwitcher) SetChannel(iface string, channel int) error {
	return nil
}

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
	s.Hopper = hopping.NewHopper("wlan0", []int{1, 6, 11}, 100*time.Millisecond, &MockSwitcher{})

	// 1. Initial State
	count, ch := s.Hopper.GetLockInfo()
	assert.Equal(t, 0, count)

	// 2. First Lock (Channel 6)
	err := s.Lock(context.Background(), "wlan0", 6)
	assert.NoError(t, err)
	count, ch = s.Hopper.GetLockInfo()
	assert.Equal(t, 1, count)
	assert.Equal(t, 6, ch)
	assert.Equal(t, hopping.StateLocked, s.Hopper.GetState(), "Hopper should be locked")

	// 3. Second Lock (Same Channel) - Ref Count Increment
	err = s.Lock(context.Background(), "wlan0", 6)
	assert.NoError(t, err)
	count, _ = s.Hopper.GetLockInfo()
	assert.Equal(t, 2, count, "Ref count should increment")

	// 4. Conflicting Lock (Channel 1) - Error
	err = s.Lock(context.Background(), "wlan0", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hopper locked on different channel")
	count, _ = s.Hopper.GetLockInfo()
	assert.Equal(t, 2, count, "Ref count should remain unchanged after error")

	// 5. Unlock (Decrement)
	err = s.Unlock(context.Background(), "wlan0")
	assert.NoError(t, err)
	count, _ = s.Hopper.GetLockInfo()
	assert.Equal(t, 1, count)
	assert.Equal(t, hopping.StateLocked, s.Hopper.GetState(), "Hopper should still be locked")

	// 6. Last Unlock (Resume)
	err = s.Unlock(context.Background(), "wlan0")
	assert.NoError(t, err)
	count, ch = s.Hopper.GetLockInfo()
	assert.Equal(t, 0, count)
	assert.Equal(t, hopping.StateHopping, s.Hopper.GetState(), "Hopper should resume")
	assert.Equal(t, 6, ch) // The channel variable might still hold the last value internally, but it's not locked.
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
	s.Hopper = hopping.NewHopper("wlan0", []int{1, 6, 11}, 100*time.Millisecond, &MockSwitcher{})

	ctx := context.Background()
	executed := false

	err := s.ExecuteWithLock(ctx, "wlan0", 6, func() error {
		executed = true
		count, _ := s.Hopper.GetLockInfo()
		assert.Equal(t, 1, count)
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, executed)
	count, _ := s.Hopper.GetLockInfo()
	assert.Equal(t, 0, count)
}
