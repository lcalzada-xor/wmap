package sniffer

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Helper to create a dummy EAPOL packet
func createEAPOLPacket(src, dst, bssid string, messageNum int) gopacket.Packet {
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
		keyInfo = 0x0080 // KeyAck set, No MIC
	case 2:
		keyInfo = 0x0100 // KeyMic set, No Ack
		dataLen = 16     // RSN IE present
	case 3:
		keyInfo = 0x0180 // KeyAck + KeyMic
	case 4:
		keyInfo = 0x0100 // KeyMic set, No Ack
		dataLen = 0      // No Key Data
	}

	// Set Key Info at offset 1 (Big Endian)
	payload[1] = byte(keyInfo >> 8)
	payload[2] = byte(keyInfo & 0xFF)

	// Set Key Data Length at offset 93 (Big Endian)
	if dataLen > 0 {
		payload[93] = byte(dataLen >> 8)
		payload[94] = byte(dataLen & 0xFF)
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
	p1 := createEAPOLPacket(bssid, client, bssid, 1)
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
	p2 := createEAPOLPacket(client, bssid, bssid, 2)
	if saved := hm.ProcessFrame(p2); !saved {
		t.Errorf("Should save on M1+M2")
	}

	// Verify File Exists
	// HandshakeManager sanitizes filenames (colons -> underscores)
	sanitizedBssid := "00_11_22_33_44_55"
	sanitizedClient := "aa_bb_cc_dd_ee_ff"
	expectedFile := filepath.Join(tmpDir, sanitizedBssid+"_"+essid+"_"+sanitizedClient+".pcap")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("Pcap file not created: %s", expectedFile)
		// List dir contents for debug
		files, _ := os.ReadDir(tmpDir)
		for _, f := range files {
			t.Logf("Found file: %s", f.Name())
		}
	}

	// 4. Test Overwrite Logic
	// Send M3. Should NOT overwrite because logic says M1+M2 count is same/less than what we just did?
	// Wait, M1+M2 = 2 messages. SavedCount = 2.
	// Sending M3 makes count 3. 3 > 2. Should overwrite.
	p3 := createEAPOLPacket(bssid, client, bssid, 3)
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
