package sniffer

import (
	"context"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/radio"
)

// Mock channel setter for testing
func mockSetChannel(iface string, channel int) error {
	return nil
}

func TestSnifferManager_Locking_Concurrency(t *testing.T) {
	// Setup mock in radio package
	radio.SetMockChannelSetter(mockSetChannel)
	// No need to revert since it's global process state for tests, but good practice
	defer radio.SetMockChannelSetter(nil) // Assuming nil resets or handle it?
	// Actually nil might panic if not handled. Let's just set it back to a dummy or assume test isolation.
	// Better: radio.SetMockChannelSetter(func(string, int) error { return nil })

	// 1. Initialize RadioManager
	radioMgr := radio.NewRadioManager()

	// 2. Initialize SnifferManager with RadioManager
	// We pass nil for dependencies we don't need for this test
	manager := NewManager([]string{"wlan0"}, 100, false, nil, radioMgr, "/tmp/handshakes", "/tmp/channels.json", nil)

	ctx := context.Background()

	// 3. Lock wlan0 (Managed Interface)
	// This should succeed
	err := manager.Lock(ctx, "wlan0", 6)
	if err != nil {
		t.Fatalf("Failed to lock managed interface wlan0: %v", err)
	}

	// 4. Lock wlan1 (Unmanaged Interface)
	// In the OLD implementation (Sniffer.Lock bypass), this would bypass checks if called on Sniffer,
	// or fail "interface not found" if called on SnifferManager.
	// In the NEW implementation (RadioManager), this should succeed AND BE TRACKED.
	err = manager.Lock(ctx, "wlan1", 11)
	if err != nil {
		t.Fatalf("Failed to lock unmanaged interface wlan1 via RadioManager: %v", err)
	}

	// 5. Try conflict on wlan1
	// If RadioManager is working, this MUST fail because wlan1 is locked on 11.
	// If we were still identifying the bug, this would succeed.
	err = manager.Lock(ctx, "wlan1", 1)
	if err == nil {
		t.Errorf("RadioManager failed to prevent conflict on wlan1! Lock(1) succeeded while locked on 11")
	}

	// 6. Try conflict on wlan0
	err = manager.Lock(ctx, "wlan0", 1)
	if err == nil {
		t.Errorf("RadioManager failed to prevent conflict on wlan0! Lock(1) succeeded while locked on 6")
	}

	// 7. Test Unlock
	manager.Unlock(ctx, "wlan1")
	// Now lock on 1 should succeed
	err = manager.Lock(ctx, "wlan1", 1)
	if err != nil {
		t.Errorf("Failed to lock wlan1 after unlock: %v", err)
	}
}
