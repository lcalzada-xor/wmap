package sniffer

import (
"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
"testing"
"time"
)

func TestPacketHandler_TriggersPause(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	hm := handshake.NewHandshakeManager(tmpDir)
	mockLoc := MockGeo{}

	var pauseDuration time.Duration
	var pauseCalled bool

	// Mock Callback
	mockPause := func(d time.Duration) {
		pauseCalled = true
		pauseDuration = d
	}

	handler := parser.NewPacketHandler(mockLoc, false, hm, mockPause)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"
	essid := "TestNet-Reactive"

	// Register network
	hm.RegisterNetwork(bssid, essid)

	// 1. Inject Beacon (Should NOT trigger pause)
	beacon := createBeaconPacket(bssid, essid, 6)
	handler.HandlePacket(beacon)

	if pauseCalled {
		t.Error("Beacon frame triggered pause incorrectly")
	}

	// 2. Inject M1 - should trigger pause due to aggressive reactive hopping
	p1 := createEAPOLPacket(bssid, client, bssid, 1)
	handler.HandlePacket(p1)

	if !pauseCalled {
		t.Error("M1 should trigger pause with Aggressive Reactive Hopping")
	} else {
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
