package sniffer

import (
	"testing"
	"time"
)

func TestPacketHandler_TriggersPause(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)
	mockLoc := MockGeo{}

	var pauseDuration time.Duration
	var pauseCalled bool

	// Mock Callback
	mockPause := func(d time.Duration) {
		pauseCalled = true
		pauseDuration = d
	}

	handler := NewPacketHandler(mockLoc, false, hm, mockPause)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"
	essid := "TestNet-Reactive"

	// 1. Inject Beacon (Should NOT trigger pause)
	// We need to register ESSID first for HandshakeManager logic usually, but not strictly for pause check if handled by ProcessFrame return.
	// ProcessFrame returns false for Beacons usually.
	hm.mu.Lock()
	hm.bssidToEssid[bssid] = essid
	hm.mu.Unlock()

	beacon := createBeaconPacket(bssid, essid, 6)
	handler.HandlePacket(beacon)

	if pauseCalled {
		t.Error("Beacon frame triggered pause incorrectly")
	}

	// 2. Inject M1 (Handshake Start)
	// ProcessFrame returns false for M1 usually unless it decides M1 is enough to "saving".
	// Our logic in HandshakeManager says:
	// "If session.Captured[1] && session.Captured[2] ... return true"
	// So M1 alone returns FALSE. Thus NO PAUSE.
	// Wait, we want to pause ON SIGHT of any handshake frame?
	// PacketHandler logic: if saved -> pause.
	// ProcessFrame logic: returns true ONLY if saveSession called.
	// saveSession called logic: if captured[1] && captured[2] ...
	//
	// ISSUE: If we only pause on "saved", we only pause AFTER capturing M1 AND M2.
	// But the goal of Reactive Hopping is to capture M2/M3/M4 *after* seeing M1 (or any part).
	// If we only pause after M2, we missed the chance to pause FOR M2.
	// We should probably update HandshakeManager.ProcessFrame to return true (or a separate "interesting" bool)
	// if it sees ANY EAPOL frame, OR update PacketHandler to inspect packet type directly too.

	// Let's test CURRENT behavior first.
	p1 := createEAPOLPacket(bssid, client, bssid, 1)
	handler.HandlePacket(p1)

	// Correcting to just check logic.
	if !pauseCalled {
		t.Error("M1 should trigger pause with Aggressive Reactive Hopping")
	} else {
		// Reset for next step
		pauseCalled = false
	}

	// 3. Inject M2 (Should trigger)
	p2 := createEAPOLPacket(client, bssid, bssid, 2)
	handler.HandlePacket(p2)

	if !pauseCalled {
		t.Error("M2 (completing handshake) did not trigger pause")
	}
	if pauseDuration != 5*time.Second {
		t.Errorf("Expected 5s pause, got %v", pauseDuration)
	}
}
