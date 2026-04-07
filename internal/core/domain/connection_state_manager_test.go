package domain

import (
	"testing"
	"time"
)

func TestConnectionStateManager_UpdateState(t *testing.T) {
	sm := NewConnectionStateManager()
	mac := "00:11:22:33:44:55"
	target := "AA:BB:CC:DD:EE:FF"

	// Initial state
	state := sm.GetState(mac)
	if state != StateDisconnected {
		t.Errorf("Expected initial state Disconnected, got %s", state)
	}

	// Auth Request
	now := time.Now()
	s, bssid := sm.UpdateState(mac, ConnectionEvent{
		Type:      EventAuthReq,
		TargetMAC: target,
		Timestamp: now,
	})

	if s != StateAuthenticating || bssid != target {
		t.Errorf("Expected Authenticating/target, got %s/%s", s, bssid)
	}

	// Data Transfer (Connected)
	s, bssid = sm.UpdateState(mac, ConnectionEvent{
		Type:      EventDataTransfer,
		TargetMAC: target,
		Timestamp: now.Add(100 * time.Millisecond),
	})

	if s != StateConnected {
		t.Errorf("Expected Connected, got %s", s)
	}

	// Deauth
	s, bssid = sm.UpdateState(mac, ConnectionEvent{
		Type:      EventDeauth,
		Timestamp: now.Add(200 * time.Millisecond),
	})

	if s != StateDisconnected || bssid != "" {
		t.Errorf("Expected Disconnected/empty, got %s/%s", s, bssid)
	}

	// Debounce check: Data transfer immediately after Deauth should be ignored
	s, bssid = sm.UpdateState(mac, ConnectionEvent{
		Type:      EventDataTransfer,
		TargetMAC: target,
		Timestamp: now.Add(250 * time.Millisecond), // Only 50ms after Deauth
	})

	if s != StateDisconnected {
		t.Errorf("Expected state to remain Disconnected due to debounce, got %s", s)
	}

	// After debounce period
	s, bssid = sm.UpdateState(mac, ConnectionEvent{
		Type:      EventDataTransfer,
		TargetMAC: target,
		Timestamp: now.Add(800 * time.Millisecond), // 600ms after Deauth (> 500ms debounce)
	})

	if s != StateConnected {
		t.Errorf("Expected Connected after debounce period, got %s", s)
	}
}

func TestConnectionStateManager_Cleanup(t *testing.T) {
	sm := NewConnectionStateManager()
	mac1 := "00:00:00:00:00:01"
	mac2 := "00:00:00:00:00:02"

	now := time.Now()
	sm.UpdateState(mac1, ConnectionEvent{Type: EventAuthReq, Timestamp: now.Add(-10 * time.Minute)})
	sm.UpdateState(mac2, ConnectionEvent{Type: EventAuthReq, Timestamp: now.Add(-1 * time.Minute)})

	// Cleanup with 5m TTL should remove mac1 but keep mac2
	evicted := sm.Cleanup(5 * time.Minute)
	if evicted != 1 {
		t.Errorf("Expected 1 evicted entry, got %d", evicted)
	}

	if sm.GetState(mac1) != StateDisconnected {
		t.Error("mac1 should have been evicted")
	}
	if sm.GetState(mac2) != StateAuthenticating {
		t.Error("mac2 should still be present")
	}
}

func TestConnectionStateManager_Sharding(t *testing.T) {
	sm := NewConnectionStateManager()
	
	// Ensure different MACs land in different shards (statistically likely for 16 shards and many MACs)
	// We just want to make sure it doesn't crash and returns correct data.
	for i := 0; i < 100; i++ {
		mac := string([]byte{byte(i)}) // dummy mac
		sm.UpdateState(mac, ConnectionEvent{Type: EventAuthReq, Timestamp: time.Now()})
	}
	
	for i := 0; i < 100; i++ {
		mac := string([]byte{byte(i)})
		if sm.GetState(mac) != StateAuthenticating {
			t.Errorf("MAC %d lost its state", i)
		}
	}
}
