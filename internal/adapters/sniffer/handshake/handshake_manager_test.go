package handshake

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// Helper to create a dummy EAPOL packet
func createEAPOLPacket(src, dst, bssid string, messageNum int, replayCounter uint64) gopacket.Packet {
	// Construct generic layers
	// Dot11
	srcMac, _ := parseMACAddr(src)
	dstMac, _ := parseMACAddr(dst)
	bssidMac, _ := parseMACAddr(bssid)

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeData,
		Flags:    0, // FromDS=0, ToDS=0 for AdHoc? Or FromDS=1 for AP->STA.
		Address1: dstMac,
		Address2: srcMac,
		Address3: bssidMac,
	}

	// LLC/SNAP usually implies EAPOL but we mock the EAPOL layer directly if possible,
	// but gopacket decoding needs the bytes.
	// Simpler: Just rely on mocks or construct minimal packet.
	// Since we can't easily construct a valid EAPOL packet from scratch without lots of boilerplate,
	// we will mock the behavior by "injecting" packets if possible, OR
	// we assume the parser works and we test the logic given a "decoded" packet.
	// But HandshakeManager takes a gopacket.Packet.

	// Let's make a real packet buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	// LLC/SNAP header is required for Dot11 Data to identify EAPOL
	llc := &layers.LLC{
		DSAP:    0xaa,
		SSAP:    0xaa,
		Control: 0x03,
	}
	snap := &layers.SNAP{
		OrganizationalCode: []byte{0, 0, 0},
		Type:               layers.EthernetTypeEAPOL,
	}

	// EAPOL Layer
	eapol := &layers.EAPOL{
		Version: 1,
		Type:    layers.EAPOLTypeKey,
		Length:  95,
	}

	// We need to trick Key info to match message 1,2,3,4
	// M1: KeyAck=1, KeyMic=0, Install=0
	// M2: KeyAck=0, KeyMic=1, Install=0
	// M3: KeyAck=1, KeyMic=1, Install=1/0
	// M4: KeyAck=0, KeyMic=1, Install=0
	// This details are inside the payload which is EAPOLKey, but layers.EAPOL is just the wrapper.
	// The payload of EAPOL is where the Key info is.

	// Payload structure for 802.11 Key Descriptor:
	// Byte 0: Descriptor Type
	// Byte 1-2: Key Information
	// Byte 3-4: Key Length
	// Byte 5-12: Replay Counter
	// ...
	// Byte 93-94: Key Data Length (WPA2)

	// So we need to craft the payload bytes correctly.
	payload := make([]byte, 100)
	payload[0] = 2 // Key Descriptor Type (RSN=2)

	// Key Info (uint16)
	var keyInfo uint16
	var dataLen uint16

	switch messageNum {
	case 1:
		keyInfo = 0x0088 // KeyAck | Pairwise
	case 2:
		keyInfo = 0x0108 // KeyMic | Pairwise
		dataLen = 16     // RSN IE present
	case 3:
		keyInfo = 0x0188 // KeyAck | KeyMic | Pairwise
	case 4:
		keyInfo = 0x0308 // KeyMic | Secure | Pairwise
		dataLen = 0      // No Key Data
	}

	// Set Key Info at offset 1 (Big Endian)
	payload[1] = byte(keyInfo >> 8)
	payload[2] = byte(keyInfo & 0xFF)

	// Set Replay Counter at offset 5 (Big Endian, 8 bytes)
	binary.BigEndian.PutUint64(payload[5:13], replayCounter)

	// Set Key Data Length at offset 93 (Big Endian)
	if dataLen > 0 {
		payload[93] = byte(dataLen >> 8)
		payload[94] = byte(dataLen & 0xFF)
	}

	// Populate MIC if KeyMic bit (0x0100) is set
	// Note: We constructed keyInfo manually above. Check bit 8.
	if (keyInfo & 0x0100) != 0 {
		for i := 77; i < 93; i++ {
			payload[i] = 0x77 // Dummy valid MIC
		}
	}

	// Add layers
	gopacket.SerializeLayers(buf, opts, dot11, llc, snap, eapol, gopacket.Payload(payload))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeDot11, gopacket.Default)
}

func parseMACAddr(s string) (net.HardwareAddr, error) {
	return net.ParseMAC(s)
}

func TestHandshakeManager_ProcessFrame(t *testing.T) {
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	bssid := "00:11:22:33:44:55"
	client := "aa:bb:cc:dd:ee:ff"
	essid := "TestNet"

	// 1. Inject Beacon to learn ESSID
	// (Skipping complex beacon inject, can manually map in test or inject beacon packet)
	hm.mu.Lock()
	hm.bssidToEssid[bssid] = essid
	hm.mu.Unlock()

	// 2. Inject M1 (AP -> STA)
	p1 := createEAPOLPacket(bssid, client, bssid, 1, 1) // RC=1
	t.Logf("P1 Layers: %v", p1.Layers())
	if saved := hm.ProcessFrame(p1); saved {
		t.Errorf("Should not save on just M1")
	}

	// Verify Session State
	hm.mu.RLock()
	key := bssid + "_" + client
	session, exists := hm.sessions[key]
	hm.mu.RUnlock()

	if !exists {
		t.Fatalf("Session not created")
	}
	if !session.Captured[1] {
		t.Errorf("M1 not captured")
	}

	// 3. Inject M2 (STA -> AP)
	// Must match Replay Counter of M1 (1)
	p2 := createEAPOLPacket(client, bssid, bssid, 2, 1)
	if saved := hm.ProcessFrame(p2); !saved {
		t.Errorf("Should save on M1+M2")
	}

	// ...

	// 4. Test Overwrite Logic
	// Send M3.
	// M3 should have ReplayCounter + 1 (2)
	p3 := createEAPOLPacket(bssid, client, bssid, 3, 2)
	if saved := hm.ProcessFrame(p3); !saved {
		t.Errorf("Should update save on M3 (count increased)")
	}

	// Check session count
	hm.mu.RLock()
	session = hm.sessions[key]
	hm.mu.RUnlock()
	if session.SavedCount != 3 {
		t.Errorf("SavedCount mismatch, got %d, want 3", session.SavedCount)
	}

	// 5. Test HasHandshake
	if !hm.HasHandshake(bssid) {
		t.Errorf("HasHandshake should be true")
	}
}

func TestHandshakeManager_HasHandshake(t *testing.T) {
	hm := NewHandshakeManager("/tmp")
	bssid := "00:00:00:00:00:01"

	if hm.HasHandshake(bssid) {
		t.Errorf("Should be false initially")
	}

	// Manually inject state
	hm.mu.Lock()
	hm.sessions[bssid+"_client"] = &HandshakeSession{
		BSSID:    bssid,
		Captured: map[uint8]bool{1: true, 2: true},
	}
	hm.mu.Unlock()

	if !hm.HasHandshake(bssid) {
		t.Errorf("Should be true after manual injection")
	}
}

func TestHandshakeManager_Concurrency(t *testing.T) {
	// Stress test concurrency
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)
	hm.RegisterNetwork("00:11:22:33:44:55", "ConcurrencyNet")

	// Run 100 concurrent packet injections
	concurrency := 100
	done := make(chan bool)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			// Mix of M1 and M2
			msg := 1
			if id%2 == 0 {
				msg = 2
			}
			p := createEAPOLPacket("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", msg, 100) // Dummy RC
			hm.ProcessFrame(p)
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Should not panic and have consistent state
	if !hm.HasHandshake("00:11:22:33:44:55") {
		t.Log("Note: Handshake might not be complete depending on race, but shouldn't crash")
	}
}

func TestHandshakeManager_Frankenstein(t *testing.T) {
	// Scenario: mixing M1 from one session with M3 from another (different Anonce)
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	bssid := "00:11:22:33:44:aa"
	client := "aa:bb:cc:dd:ee:00"

	// 1. M1 with Anonce 0 (default)
	p1 := createEAPOLPacket(bssid, client, bssid, 1, 100)
	saved := hm.ProcessFrame(p1) // Session created, Anonce stored (all 0s)
	assert.False(t, saved, "M1 alone should not trigger save")

	// Verify session
	hm.mu.RLock()
	session, exists := hm.sessions[bssid+"_"+client]
	hm.mu.RUnlock()
	assert.True(t, exists)
	assert.True(t, session.HasReplayCounter)

	// 2. M2 (STA->AP) matches RC.
	p2 := createEAPOLPacket(client, bssid, bssid, 2, 100)
	saved = hm.ProcessFrame(p2)
	assert.True(t, saved, "M2 should be accepted and save the session")

	// 3. M3 (AP->STA) with WRONG Anonce.
	// Helper to create packet with specific nonce
	createPacketWithNonce := func(nonceByte byte) gopacket.Packet {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		srcMac, _ := net.ParseMAC(bssid)
		dstMac, _ := net.ParseMAC(client)
		bssidMac, _ := net.ParseMAC(bssid)

		dot11 := &layers.Dot11{
			Type:     layers.Dot11TypeData,
			Address1: dstMac, Address2: srcMac, Address3: bssidMac,
		}
		llc := &layers.LLC{DSAP: 0xaa, SSAP: 0xaa, Control: 0x03}
		snap := &layers.SNAP{OrganizationalCode: []byte{0, 0, 0}, Type: layers.EthernetTypeEAPOL}
		eapol := &layers.EAPOL{Version: 1, Type: layers.EAPOLTypeKey, Length: 95}

		payload := make([]byte, 100)
		payload[0] = 2
		keyInfo := uint16(0x0188) // M3: Ack | Mic | Pairwise
		payload[1] = byte(keyInfo >> 8)
		payload[2] = byte(keyInfo & 0xFF)
		binary.BigEndian.PutUint64(payload[5:13], 101) // RC+1

		// Set Nonce
		for i := 13; i < 45; i++ {
			payload[i] = nonceByte
		}
		// Data Length 0
		payload[93] = 0
		payload[94] = 0

		gopacket.SerializeLayers(buf, opts, dot11, llc, snap, eapol, gopacket.Payload(payload))
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeDot11, gopacket.Default)
	}

	p3 := createPacketWithNonce(0xDD) // Nonce 0xDD... != 0x00...

	// Should be rejected
	saved = hm.ProcessFrame(p3)
	assert.False(t, saved, "M3 with wrong Anonce should be rejected")
}
