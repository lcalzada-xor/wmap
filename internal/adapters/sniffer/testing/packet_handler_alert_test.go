package sniffer

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
)

func TestHandlePacket_HandshakeAlert(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	hm := handshake.NewHandshakeManager(tmpDir)
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, true, hm, nil, nil)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"
	essid := "TestNet-Alert"

	// 1. Inject Beacon to learn ESSID
	// 1. Inject Beacon to learn ESSID
	hm.RegisterNetwork(bssid, essid)

	// 4. Inject M3 check prep
	anonce := make([]byte, 32)
	anonce[0] = 0xAA

	// 2. Inject M1 (No Alert Expected)
	// Use explicit Replay Counter 1 and Nonce
	p1 := createEAPOLPacket(bssid, client, bssid, 1, EAPOLOptions{ReplayCounter: 1, Nonce: anonce})
	device, alert := handler.HandlePacket(p1)

	if alert != nil {
		t.Errorf("Unexpected alert on M1: %v", alert)
	}

	// 3. Inject M2 (Alert Expected)
	// RC must match M1
	p2 := createEAPOLPacket(client, bssid, bssid, 2, EAPOLOptions{ReplayCounter: 1})
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

	// 4. Inject M3 (Alert Expected because it completes Anonce if missing, or just updates session)
	// RC should be M1+1 usually for M3? Or sometimes M1.
	// HandshakeManager logic: expectedRC := session.ReplayCounter + 1.
	// So let's use RC=2.
	// Also provide Anonce (M3 has it).
	// anonce defined above
	p3 := createEAPOLPacket(bssid, client, bssid, 3, EAPOLOptions{ReplayCounter: 2, Nonce: anonce})
	time.Sleep(1 * time.Millisecond)

	_, alert3 := handler.HandlePacket(p3)
	if alert3 == nil {
		t.Errorf("Expected alert update on M3 capture (better handshake)")
	}
}
