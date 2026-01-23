package sniffer

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestHandlePacket_M1Anomaly_ZeroNonce(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	hm := handshake.NewHandshakeManager(tmpDir)
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, true, hm, nil, nil)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"

	// Create Zero Nonce (32 bytes of 0x00)
	zeroNonce := make([]byte, 32)

	// Create EAPOL Packet: AP -> Client (FromDS=1 is mostly implied by bssid, client args in helper? need to verify helper)
	// createEAPOLPacket(src, dst, bssid, type...)
	// AP -> Client: Source=BSSID, Dest=Client

	// Assuming createEAPOLPacket sets FromDS based on match with BSSID?
	// I need to check createEAPOLPacket implementation in test_utils_test.go to be sure.
	// But assuming standard mocking:

	p := createEAPOLPacket(bssid, client, bssid, 1, EAPOLOptions{
		ReplayCounter: 1,
		Nonce:         zeroNonce,
		IsFromDS:      true, // Explicitly set if supported, or ensure src=bssid sets it
	})

	_, alert := handler.HandlePacket(p)

	if alert == nil {
		t.Errorf("Expected WEAK_CRYPTO_ZERO_NONCE alert, got nil")
		return
	}

	if alert.Subtype != "WEAK_CRYPTO_ZERO_NONCE" {
		t.Errorf("Expected subtype WEAK_CRYPTO_ZERO_NONCE, got %s", alert.Subtype)
	}

	if alert.Severity != domain.SeverityCritical {
		t.Errorf("Expected Critical severity, got %v", alert.Severity)
	}
}

func TestHandlePacket_M1Anomaly_BadRNG(t *testing.T) {
	tmpDir := t.TempDir()
	hm := handshake.NewHandshakeManager(tmpDir)
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, true, hm, nil, nil)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"

	// Create Repeating Pattern Nonce (32 bytes of 0xAA)
	badNonce := make([]byte, 32)
	for i := range badNonce {
		badNonce[i] = 0xAA
	}

	p := createEAPOLPacket(bssid, client, bssid, 1, EAPOLOptions{
		ReplayCounter: 1,
		Nonce:         badNonce,
		IsFromDS:      true,
	})

	_, alert := handler.HandlePacket(p)

	if alert == nil {
		t.Errorf("Expected WEAK_CRYPTO_BAD_RNG alert, got nil")
		return
	}

	if alert.Subtype != "WEAK_CRYPTO_BAD_RNG" {
		t.Errorf("Expected subtype WEAK_CRYPTO_BAD_RNG, got %s", alert.Subtype)
	}
}
