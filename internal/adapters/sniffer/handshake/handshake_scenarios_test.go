package handshake

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// === Helpers ===

// struct to define strict packet parameters
type packetParams struct {
	SRC           string
	DST           string
	BSSID         string
	MsgNum        int
	ReplayCounter uint64
	Nonce         []byte // Optional
	IsGroup       bool   // If true, unset Pairwise bit
}

func makeEAPOL(p packetParams) gopacket.Packet {
	// Defaults
	if p.SRC == "" {
		p.SRC = "00:11:22:33:44:55"
	}
	if p.DST == "" {
		p.DST = "aa:bb:cc:dd:ee:ff" // Station
	}
	if p.BSSID == "" {
		p.BSSID = "00:11:22:33:44:55"
	}

	srcMac, _ := parseMACAddr(p.SRC)
	dstMac, _ := parseMACAddr(p.DST)
	bssidMac, _ := parseMACAddr(p.BSSID)

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeData,
		Address1: dstMac,
		Address2: srcMac,
		Address3: bssidMac,
	}

	// Fake LLC/SNAP
	llc := &layers.LLC{DSAP: 0xaa, SSAP: 0xaa, Control: 0x03}
	snap := &layers.SNAP{OrganizationalCode: []byte{0, 0, 0}, Type: layers.EthernetTypeEAPOL}
	eapol := &layers.EAPOL{Version: 1, Type: layers.EAPOLTypeKey, Length: 95}

	// Payload
	payload := make([]byte, 100)
	payload[0] = 2 // RSN

	var keyInfo uint16
	var dataLen uint16

	// Base flags: KeyDescriptorVersion=2 (AES)
	baseFlags := uint16(2)
	if !p.IsGroup {
		baseFlags |= 0x0008 // Set Pairwise bit
	}

	switch p.MsgNum {
	case 1:
		// Ack=1, Mic=0
		keyInfo = baseFlags | 0x0080
	case 2:
		// Ack=0, Mic=1
		keyInfo = baseFlags | 0x0100
		dataLen = 16
	case 3:
		// Ack=1, Mic=1, Install=1 (sometimes)
		keyInfo = baseFlags | 0x0180 | 0x0040
	case 4:
		// Ack=0, Mic=1, Secure=1
		keyInfo = baseFlags | 0x0100 | 0x0200
		dataLen = 0
	}

	if p.IsGroup {
		// Group Key Handshake:
		// M1 (Group Key): Ack=1, Mic=1, Secure=1.
		// M2 (Group Key): Ack=0, Mic=1.
		// Just manual override for test purposes
		if p.MsgNum == 1 {
			keyInfo = 0x0380 // Ack|Mic|Secure
		}
	}

	binary.BigEndian.PutUint16(payload[1:3], keyInfo)
	binary.BigEndian.PutUint64(payload[5:13], p.ReplayCounter)

	// Nonce
	if len(p.Nonce) == 32 {
		copy(payload[13:45], p.Nonce)
	}

	if dataLen > 0 {
		binary.BigEndian.PutUint16(payload[93:95], dataLen)
	}

	// Helper to populate MIC if KeyMic bit (bit 8 -> 0x0100) is set
	if (keyInfo & 0x0100) != 0 {
		for i := 77; i < 93; i++ {
			payload[i] = 0x77 // Dummy valid MIC
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, dot11, llc, snap, eapol, gopacket.Payload(payload))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeDot11, gopacket.Default)
	pkt.Metadata().CaptureInfo.CaptureLength = len(buf.Bytes())
	pkt.Metadata().CaptureInfo.Length = len(buf.Bytes())
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	return pkt
}

// === Tests ===

func TestScenario_Perfect4Way(t *testing.T) {
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:00"
	sta := "aa:aa:aa:aa:aa:00"

	// M1
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 10}))
	// M2
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 2, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 10}))
	// Check
	if !hm.HasHandshake(ap) {
		t.Error("Should have handshake after M1+M2")
	}

	// M3
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 3, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 11}))
	// M4
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 4, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 11}))

	// Verify session captured map
	session := getSession(hm, ap, sta)
	assert.True(t, session.Captured[1], "M1 Missing")
	assert.True(t, session.Captured[2], "M2 Missing")
	assert.True(t, session.Captured[3], "M3 Missing")
	assert.True(t, session.Captured[4], "M4 Missing")
}

func TestScenario_PacketLoss_MidStreamJoin(t *testing.T) {
	// Sniffer starts listening late. Misses M1.
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:01"
	sta := "aa:aa:aa:aa:aa:01"
	anonce := make([]byte, 32)
	anonce[0] = 0xAA // Marker

	// Missed M1...

	// Capture M2 (STA->AP)
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 2, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 20}))
	assert.False(t, hm.HasHandshake(ap), "M2 only is not enough")

	// Capture M3 (AP->STA) - Contains Anonce
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 3, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 21, Nonce: anonce}))

	assert.True(t, hm.HasHandshake(ap), "M2+M3 should be valid")

	session := getSession(hm, ap, sta)
	assert.Equal(t, anonce, session.Anonce, "Anonce not recovered")
}

func TestScenario_PacketLoss_MissedM2(t *testing.T) {
	// Captures M1, Misses M2, Captures M3.
	// This is NOT a complete handshake for cracking usually (Need SNonce from M2).
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:02"
	sta := "aa:aa:aa:aa:aa:02"

	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 30}))
	// Missed M2
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 3, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 31}))

	assert.False(t, hm.HasHandshake(ap), "Missing M2 (SNonce) -> Invalid Handshake")
}

func TestScenario_Retransmissions(t *testing.T) {
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:03"
	sta := "aa:aa:aa:aa:aa:03"

	// M1 sent twice
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 40}))
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 40}))

	session := getSession(hm, ap, sta)
	assert.Equal(t, 0, session.SavedCount, "Duplicate M1 shouldn't trigger save or reset")
	assert.True(t, session.Captured[1])

	// M2 sent twice
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 2, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 40}))

	// First M2 triggers save
	// Wait for async save? (Testing Logic, not File IO primarily)
	time.Sleep(10 * time.Millisecond) // Give channel a moment? SavedCount is updated synchronously in ProcessFrame BEFORE sending to channel!
	// Correction: SavedCount is updated in HM structure immediately.

	assert.True(t, hm.HasHandshake(ap))
	firstSaveCount := session.SavedCount

	// Duplicate M2
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 2, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 40}))

	assert.Equal(t, firstSaveCount, session.SavedCount, "Duplicate M2 shouldn't trigger new save if content count same")
}

func TestScenario_SessionReset(t *testing.T) {
	// AP crashes or restarts handshake (New M1 with different RC)
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:04"
	sta := "aa:aa:aa:aa:aa:04"

	// Session 1
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 50}))
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 2, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 50}))
	assert.True(t, hm.HasHandshake(ap))

	// New Session (M1 with RC 9000)
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 9000}))

	session := getSession(hm, ap, sta)
	assert.Equal(t, uint64(9000), session.ReplayCounter)
	assert.True(t, session.Captured[1])
	assert.False(t, session.Captured[2], "New session should clear old M2")
	assert.False(t, hm.HasHandshake(ap), "New session incomplete")
}

func TestScenario_GroupKeyHandshake(t *testing.T) {
	// Group Key Handshake (M1 with Pairwise=0) should be ignored or not disrupt
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:05"
	sta := "aa:aa:aa:aa:aa:05"

	// Valid Session Start
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 60}))

	// Group Key Frame (MsgNum calc will return 0 or specific logic)
	// Our makeEAPOL handles IsGroup flag
	gk := makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 61, IsGroup: true})

	hm.ProcessFrame(gk)

	session := getSession(hm, ap, sta)
	// Should not have reset the session
	assert.Equal(t, uint64(60), session.ReplayCounter, "Group Key frame shouldn't reset Pairwise session")
}

func TestScenario_CornerCases(t *testing.T) {
	hm := NewHandshakeManager(t.TempDir())
	ap := "00:11:22:33:44:06"
	sta := "aa:aa:aa:aa:aa:06"

	// WPA2 uses RC+1 for M3/M4 usually.
	// Some APs use RC for M3 too.
	// Case: M1(RC=10) -> M2(RC=10) -> M3(RC=10) [Relaxed compliance]

	anonce := []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}

	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 1, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 10, Nonce: anonce}))
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 2, SRC: sta, DST: ap, BSSID: ap, ReplayCounter: 10}))
	// M3 with SAME RC (10) instead of 11.
	hm.ProcessFrame(makeEAPOL(packetParams{MsgNum: 3, SRC: ap, DST: sta, BSSID: ap, ReplayCounter: 10, Nonce: anonce}))

	session := getSession(hm, ap, sta)
	assert.True(t, session.Captured[3], "Should accept M3 with same RC if Nonce matches (Relaxed compliance)")
}

func getSession(hm *HandshakeManager, bssid, sta string) *HandshakeSession {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.sessions[bssid+"_"+sta]
}
