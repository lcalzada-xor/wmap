package sniffer

import (
	"testing"
	"time"
)

func TestHandlePacket_HandshakeAlert(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)
	mockLoc := MockGeo{}
	handler := NewPacketHandler(mockLoc, true, hm, nil)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"
	essid := "TestNet-Alert"

	// 1. Inject Beacon to learn ESSID
	hm.mu.Lock()
	hm.bssidToEssid[bssid] = essid
	hm.mu.Unlock()

	// 2. Inject M1 (No Alert Expected)
	p1 := createEAPOLPacket(bssid, client, bssid, 1)
	device, alert := handler.HandlePacket(p1)

	if alert != nil {
		t.Errorf("Unexpected alert on M1: %v", alert)
	}

	// 3. Inject M2 (Alert Expected)
	p2 := createEAPOLPacket(client, bssid, bssid, 2)
	device, alert = handler.HandlePacket(p2)

	if alert == nil {
		t.Errorf("Expected HANDSHAKE_CAPTURED alert on M2")
	} else {
		if alert.Type != "HANDSHAKE_CAPTURED" {
			t.Errorf("Expected alert type HANDSHAKE_CAPTURED, got %s", alert.Type)
		}
		if alert.Subtype != "WPA_HANDSHAKE" {
			t.Errorf("Expected subtype WPA_HANDSHAKE, got %s", alert.Subtype)
		}
	}

	if device != nil {
		// Expect nil because alert returns early
	}

	p3 := createEAPOLPacket(bssid, client, bssid, 3)
	time.Sleep(1 * time.Millisecond)

	_, alert3 := handler.HandlePacket(p3)
	if alert3 == nil {
		t.Errorf("Expected alert update on M3 capture (better handshake)")
	}
}
