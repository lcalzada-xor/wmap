package domain

import (
	"testing"
	"time"
)

func TestConnectionStateManager_UpdateState(t *testing.T) {
	sm := NewConnectionStateManager()
	deviceMAC := "00:11:22:33:44:55"
	targetBSSID := "AA:BB:CC:DD:EE:FF"

	// 1. Initial State -> Auth
	state, target := sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventAuthReq,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateAuthenticating {
		t.Errorf("Expected StateAuthenticating, got %v", state)
	}
	if target != targetBSSID {
		t.Errorf("Expected target %s, got %s", targetBSSID, target)
	}

	// 2. Auth -> Assoc
	state, target = sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventAssocReq,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateAssociating {
		t.Errorf("Expected StateAssociating, got %v", state)
	}

	// 3. Assoc -> EAPOL (Handshake)
	state, target = sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventEAPOL,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateHandshake {
		t.Errorf("Expected StateHandshake, got %v", state)
	}

	// 4. EAPOL -> Data (Connected)
	state, target = sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDataTransfer,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateConnected {
		t.Errorf("Expected StateConnected, got %v", state)
	}

	// 5. Deauth -> Disconnected
	state, target = sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDeauth,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateDisconnected {
		t.Errorf("Expected StateDisconnected, got %v", state)
	}
	if target != "" {
		t.Errorf("Expected empty target on deauth, got %s", target)
	}
}

func TestConnectionStateManager_DataConfirm(t *testing.T) {
	sm := NewConnectionStateManager()
	deviceMAC := "00:11:22:33:44:55"
	targetBSSID := "AA:BB:CC:DD:EE:FF"

	// Direct Data from Disconnected -> Connected
	state, target := sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDataTransfer,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateConnected {
		t.Errorf("Expected StateConnected from direct data, got %v", state)
	}
	if target != targetBSSID {
		t.Errorf("Expected target %s, got %s", targetBSSID, target)
	}
}

func TestConnectionStateManager_Debounce(t *testing.T) {
	sm := NewConnectionStateManager()
	deviceMAC := "00:11:22:33:44:55"
	targetBSSID := "AA:BB:CC:DD:EE:FF"

	// 1. Set to Connected
	sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDataTransfer,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	// 2. Deauth (sets LastStateChange to Now)
	sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDeauth,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	// 3. Fast Reconnect attempt via Data (Ghost packet)
	// Should be ignored due to < 500ms debounce
	state, _ := sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDataTransfer,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: time.Now(),
	})

	if state != StateDisconnected {
		t.Errorf("Expected StateDisconnected (Debounced), got %v", state)
	}

	// 4. Valid Reconnect after delay
	// We simulate a packet from the future
	futureTime := time.Now().Add(1 * time.Second)
	state, _ = sm.UpdateState(deviceMAC, ConnectionEvent{
		Type:      EventDataTransfer,
		SourceMAC: deviceMAC,
		TargetMAC: targetBSSID,
		Timestamp: futureTime,
	})

	if state != StateConnected {
		t.Errorf("Expected StateConnected after delay, got %v", state)
	}
}
