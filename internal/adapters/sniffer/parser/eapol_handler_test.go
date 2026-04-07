package parser

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// mockHandshakeManager is a dummy implementation for testing
type mockHandshakeManager struct{}
func (m *mockHandshakeManager) ProcessFrame(packet gopacket.Packet) bool { return false }
func (m *mockHandshakeManager) SavePMKID(packet gopacket.Packet, bssid, essid string) {}
func (m *mockHandshakeManager) SaveHandshake(bssid, essid string, m1, m2, m3, m4 gopacket.Packet) {}
func (m *mockHandshakeManager) GetHandshakeFile(bssid string) string { return "" }
func (m *mockHandshakeManager) HasHandshake(bssid string) bool { return false }


func createTestDot11(fromDS bool) *layers.Dot11 {
	d := &layers.Dot11{
		Type:           layers.Dot11TypeData,
		Address1:       make([]byte, 6),
		Address2:       make([]byte, 6),
		Address3:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
	if fromDS {
		d.Flags |= layers.Dot11FlagsFromDS
	}
	return d
}

func createTestEAPOL(payload []byte) *layers.EAPOL {
	return &layers.EAPOL{
		Version: 1,
		Type:    layers.EAPOLTypeKey,
		Length:  uint16(len(payload)),
		BaseLayer: layers.BaseLayer{Payload: payload},
	}
}

func TestAnalyzeM1_ZeroNonce(t *testing.T) {
	handler := &PacketHandler{
		HandshakeManager: &mockHandshakeManager{},
	}
	
	// payload: Descriptor (1), KeyInfo (2), KeyLen (2), Replay (8), Nonce (32)
	payload := make([]byte, 1+2+2+8+32)
	payload[0] = 2 // 802.11i descriptor
	
	// Key Info: Key Ack set (bit 7), Key MIC not set (bit 8)
	// payload[1] bits 15-8, payload[2] bits 7-0
	// Key Ack is bit 7 -> payload[2] = 0x80
	payload[2] = 0x80
	
	// nonce is zero implicitly
	
	dot11 := createTestDot11(true) // From AP
	eapol := createTestEAPOL(payload)
	
	alert := handler.analyzeM1(dot11, eapol)
	assert.NotNil(t, alert)
	assert.Equal(t, "WEAK_CRYPTO_ZERO_NONCE", alert.Subtype)
}

func TestAnalyzeM1_RepeatingNonce(t *testing.T) {
	handler := &PacketHandler{
		HandshakeManager: &mockHandshakeManager{},
	}
	
	payload := make([]byte, 1+2+2+8+32)
	payload[0] = 2 // 802.11i descriptor
	payload[2] = 0x80 // Key Ack set
	
	// Set repeating nonce (0xAA)
	for i := 13; i < 13+32; i++ {
		payload[i] = 0xAA
	}
	
	dot11 := createTestDot11(true) // From AP
	eapol := createTestEAPOL(payload)
	
	alert := handler.analyzeM1(dot11, eapol)
	assert.NotNil(t, alert)
	assert.Equal(t, "WEAK_CRYPTO_BAD_RNG", alert.Subtype)
}

func TestAnalyzeM1_ValidNonce(t *testing.T) {
	handler := &PacketHandler{
		HandshakeManager: &mockHandshakeManager{},
	}
	
	payload := make([]byte, 1+2+2+8+32+10)
	payload[0] = 2 // 802.11i descriptor
	payload[2] = 0x80 // Key Ack set
	
	// Randomish nonce
	for i := 13; i < 13+32; i++ {
		payload[i] = byte(i)
	}
	
	dot11 := createTestDot11(true) // From AP
	eapol := createTestEAPOL(payload)
	
	alert := handler.analyzeM1(dot11, eapol)
	assert.Nil(t, alert)
}

func TestAnalyzeM1_NotM1(t *testing.T) {
	handler := &PacketHandler{
		HandshakeManager: &mockHandshakeManager{},
	}
	
	payload := make([]byte, 1+2+2+8+32)
	payload[0] = 2 // 802.11i descriptor
	
	// Key Info: Key Ack NOT set, Key MIC set
	payload[1] = 0x01
	payload[2] = 0x00
	
	// Zero nonce
	
	dot11 := createTestDot11(true) // From AP
	eapol := createTestEAPOL(payload)
	
	// Should return nil because it's not M1
	alert := handler.analyzeM1(dot11, eapol)
	assert.Nil(t, alert)
}

func TestDetectPMKID_ShortPayload(t *testing.T) {
	handler := &PacketHandler{
		HandshakeManager: &mockHandshakeManager{},
	}
	
	payload := make([]byte, 50) // Too short
	
	dot11 := createTestDot11(true) // From AP
	eapol := createTestEAPOL(payload)
	
	detected := handler.detectPMKID(nil, dot11, eapol)
	assert.False(t, detected)
}

func TestDetectPMKID_Valid(t *testing.T) {
	handler := &PacketHandler{
		HandshakeManager: &mockHandshakeManager{},
	}
	
	// 95 bytes base header + 22 bytes PMKID IE (type 221, length 20, oui 00-0f-ac, oui type 4)
	payload := make([]byte, 95+22)
	
	// Key Data Length (22)
	payload[93] = 0
	payload[94] = 22
	
	// PMKID IE (KDE)
	payload[95] = 221 // Vendor Specific
	payload[96] = 20  // Length
	payload[97] = 0x00
	payload[98] = 0x0f
	payload[99] = 0xac
	payload[100] = 4 // PMKID
	// rest is PMKID bits
	
	dot11 := createTestDot11(true) // From AP
	eapol := createTestEAPOL(payload)
	
	detected := handler.detectPMKID(nil, dot11, eapol)
	assert.True(t, detected)
}
