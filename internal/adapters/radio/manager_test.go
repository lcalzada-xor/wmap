package radio

import (
	"context"
	"testing"
	"time"
)

type MockHandler struct {
	Paused bool
}

func (m *MockHandler) PauseHopper(d time.Duration) {
	m.Paused = true
}

func TestRadioManager_Locking(t *testing.T) {
	// Mock driver
	originalSetter := channelSetter
	defer func() { channelSetter = originalSetter }()
	channelSetter = func(iface string, ch int) error { return nil }

	rm := NewRadioManager()
	ctx := context.Background()
	iface := "wlan0"

	// 1. First Lock
	if err := rm.Lock(ctx, iface, 6); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Verify state
	state, _ := rm.interfaces.Load(iface)
	if s := state.(*ifaceState); s.activeChannel != 6 {
		t.Errorf("Expected active lock on ch 6, got %d", s.activeChannel)
	}
	if s := state.(*ifaceState); s.lockCount != 1 {
		t.Errorf("Expected count 1, got %d", s.lockCount)
	}

	// 2. Re-entry Lock (Same channel)
	if err := rm.Lock(ctx, iface, 6); err != nil {
		t.Fatalf("Relock failed: %v", err)
	}
	state, _ = rm.interfaces.Load(iface)
	if s := state.(*ifaceState); s.lockCount != 2 {
		t.Errorf("Expected count 2, got %d", s.lockCount)
	}

	// 3. Conflict Lock (Different channel)
	if err := rm.Lock(ctx, iface, 11); err == nil {
		t.Fatal("Expected error for conflicting lock, got nil")
	}

	// 4. Unlock
	rm.Unlock(ctx, iface) // count 1
	rm.Unlock(ctx, iface) // count 0, released

	state, _ = rm.interfaces.Load(iface)
	if s := state.(*ifaceState); s.lockCount > 0 {
		t.Error("Expected interface to be inactive after unlock")
	}

	// 5. New Lock on different channel (should work now)
	if err := rm.Lock(ctx, iface, 11); err != nil {
		t.Fatalf("New lock failed: %v", err)
	}
	state, _ = rm.interfaces.Load(iface)
	if s := state.(*ifaceState); s.activeChannel != 11 {
		t.Errorf("Expected active lock on ch 11")
	}
}

func TestRadioManager_Handler(t *testing.T) {
	rm := NewRadioManager()
	handler := &MockHandler{}
	rm.RegisterHandler("wlan0", handler)

	// Mock driver
	originalSetter := channelSetter
	defer func() { channelSetter = originalSetter }()
	channelSetter = func(iface string, ch int) error { return nil }

	rm.Lock(context.Background(), "wlan0", 1)

	if !handler.Paused {
		t.Error("Handler should have been paused")
	}
}
