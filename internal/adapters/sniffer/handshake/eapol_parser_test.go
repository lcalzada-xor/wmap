package handshake

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func createTestEAPOLFrame(t *testing.T, keyType uint8, keyInfo uint16, replayCounter uint64, nonce []byte, mic []byte, data []byte) gopacket.Packet {
	// Payload construction
	// DescType(1) + KeyInfo(2) + KeyLen(2) + RC(8) + Nonce(32) + IV(16) + RSC(8) + ID(8) + MIC(16) + DataLen(2) + Data(N)
	payload := make([]byte, 95+len(data))
	payload[0] = 2 // RSNA Key Descriptor (WPA2)

	binary.BigEndian.PutUint16(payload[1:3], keyInfo)
	binary.BigEndian.PutUint16(payload[3:5], 16) // Key Length (TKIP/AES)
	binary.BigEndian.PutUint64(payload[5:13], replayCounter)
	if nonce != nil {
		copy(payload[13:45], nonce)
	}
	// IV (16) zero
	// RSC (8) zero
	// ID (8) zero
	if mic != nil {
		copy(payload[77:93], mic)
	}
	binary.BigEndian.PutUint16(payload[93:95], uint16(len(data)))
	if len(data) > 0 {
		copy(payload[95:], data)
	}

	// Create a dummy packet with EAPOL layer
	// EAPOL Header: Version(1) + Type(1) + Length(2)
	header := []byte{1, 3, 0, 0} // Type 3=Key.
	totalLen := len(payload)
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))

	fullData := append(header, payload...)

	pkt := gopacket.NewPacket(fullData, layers.LayerTypeEAPOL, gopacket.Default)
	return pkt
}

func TestParseEAPOLKey_ValidM1(t *testing.T) {
	// M1: KeyAck=1, KeyMIC=0, KeyInstall=0, KeyPairwise=1, KeySecure=0
	// Info: 0000 0000 1000 1001 (0x0089 with Version 1) or 0x008A (Version 2)
	// Pairwise(bit 3)=1, Ack(bit 7)=1.
	keyInfo := uint16(KeyInfoKeyType | KeyInfoKeyAck | 2) // Version 2

	nonce := make([]byte, 32)
	nonce[0] = 0xAA // Anonce

	pkt := createTestEAPOLFrame(t, 3, keyInfo, 1, nonce, nil, nil)

	frame, err := ParseEAPOLKey(pkt)
	assert.NoError(t, err)
	assert.NotNil(t, frame)
	assert.Equal(t, uint64(1), frame.ReplayCounter)
	assert.Equal(t, nonce, frame.Nonce)
	assert.True(t, frame.IsPairwise)
	assert.False(t, frame.HasMIC)

	msgNum := frame.DetermineMessageNumber()
	assert.Equal(t, 1, msgNum)
}

func TestParseEAPOLKey_ValidM2(t *testing.T) {
	// M2: KeyMIC=1, KeyAck=0, KeySecure=0.
	// Info: MIC(bit 8)=1, Pairwise=1.
	keyInfo := uint16(KeyInfoKeyType | KeyInfoKeyMIC | 2)

	nonce := make([]byte, 32)
	nonce[0] = 0xBB // Snonce
	mic := make([]byte, 16)
	mic[0] = 0xCC
	data := []byte{0x30, 0x14, 0x01, 0x00} // RSN IE example

	pkt := createTestEAPOLFrame(t, 3, keyInfo, 1, nonce, mic, data)

	frame, err := ParseEAPOLKey(pkt)
	assert.NoError(t, err)
	assert.True(t, frame.HasMIC)
	assert.False(t, frame.HasAck)
	assert.Equal(t, 2, frame.DetermineMessageNumber())
}

func TestParseEAPOLKey_ValidM3(t *testing.T) {
	// M3: KeyMIC=1, KeyAck=1, KeySecure=0/1(Install).
	// Info: MIC=1, Ack=1, Pairwise=1
	keyInfo := uint16(KeyInfoKeyType | KeyInfoKeyMIC | KeyInfoKeyAck | KeyInfoInstall | 2)

	pkt := createTestEAPOLFrame(t, 3, keyInfo, 2, nil, []byte{1}, nil)
	frame, err := ParseEAPOLKey(pkt)
	assert.NoError(t, err)
	assert.Equal(t, 3, frame.DetermineMessageNumber())
}

func TestParseEAPOLKey_Truncated(t *testing.T) {
	// Create partial packet
	// Header (4) + Partial Payload (50)
	raw := make([]byte, 54)
	raw[1] = 3 // Key Type
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEAPOL, gopacket.Default)

	frame, err := ParseEAPOLKey(pkt)
	assert.Error(t, err)
	assert.Nil(t, frame)
	assert.Contains(t, err.Error(), "payload too short")
}
