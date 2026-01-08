package sniffer

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	defaultSessionTimeout = 5 * time.Minute
	cleanupInterval       = 1 * time.Minute
	maxFramesPerSession   = 20
)

// HandshakeManager handles the capture and storage of WPA/WPA2 handshakes.
type HandshakeManager struct {
	mu           sync.RWMutex
	baseDir      string
	bssidToEssid map[string]string
	sessions     map[string]*HandshakeSession
}

// HandshakeSession represents a capture session for a specific BSSID+Station pair.
type HandshakeSession struct {
	BSSID      string
	StationMAC string
	ESSID      string
	Frames     []gopacket.Packet
	LastUpdate time.Time
	Captured   map[uint8]bool // Tracks 1=M1, 2=M2, 3=M3, 4=M4
	SavedCount int            // How many unique messages were in the last saved file
}

// NewHandshakeManager creates a new manager.
func NewHandshakeManager(baseDir string) *HandshakeManager {
	// Ensure directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		log.Printf("ERROR: Could not create handshake capture dir: %v", err)
	}

	hm := &HandshakeManager{
		baseDir:      baseDir,
		bssidToEssid: make(map[string]string),
		sessions:     make(map[string]*HandshakeSession),
	}

	// Start cleanup routine
	go hm.startCleanupRoutine()

	return hm
}

func (hm *HandshakeManager) startCleanupRoutine() {
	ticker := time.NewTicker(cleanupInterval)
	for range ticker.C {
		hm.CleanupSessions()
	}
}

// CleanupSessions removes sessions that haven't been updated recently.
func (hm *HandshakeManager) CleanupSessions() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	now := time.Now()
	for key, session := range hm.sessions {
		if now.Sub(session.LastUpdate) > defaultSessionTimeout {
			delete(hm.sessions, key)
		}
	}
}

// ProcessFrame inspects packets for Beacons (to map BSSID->ESSID) and EAPOL frames.
// Returns true if a handshake file was saved/updated.
func (hm *HandshakeManager) ProcessFrame(packet gopacket.Packet) bool {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return false
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return false
	}

	// 1. Process Beacons to learn ESSIDs
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		bssid := dot11.Address3.String()
		if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
			// Extract SSID from IEs
			essid := getSSIDFromPacket(packet)
			if essid != "" && essid != "<HIDDEN>" {
				hm.mu.Lock()
				hm.bssidToEssid[bssid] = essid
				hm.mu.Unlock()
			}
		}
		return false
	}

	// 2. Process EAPOL Frames
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		return hm.handleEAPOL(packet, dot11)
	}

	return false
}

func (hm *HandshakeManager) handleEAPOL(packet gopacket.Packet, dot11 *layers.Dot11) bool {
	// EAPOL frames are Data frames.
	// Address1 = Recipient (DA)
	// Address2 = Transmitter (SA)
	// Address3 = BSSID

	bssid := dot11.Address3.String()
	src := dot11.Address2.String()
	dst := dot11.Address1.String()

	// Determine Station MAC (The one that is NOT the BSSID)
	// Usually:
	// AP -> STA (Key 1/4, 3/4): Src=BSSID, Dst=STA
	// STA -> AP (Key 2/4, 4/4): Src=STA, Dst=BSSID
	var stationMac string
	if src == bssid {
		stationMac = dst
	} else {
		stationMac = src
	}

	key := bssid + "_" + stationMac

	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Get or Create Session
	session, exists := hm.sessions[key]
	if !exists {
		essid := hm.bssidToEssid[bssid]
		if essid == "" {
			essid = "unknown"
		}
		session = &HandshakeSession{
			BSSID:      bssid,
			StationMAC: stationMac,
			ESSID:      essid,
			Frames:     make([]gopacket.Packet, 0),
			Captured:   make(map[uint8]bool),
		}
		hm.sessions[key] = session
	}

	// Update ESSID if we learned it later
	if session.ESSID == "unknown" {
		if val, ok := hm.bssidToEssid[bssid]; ok {
			session.ESSID = val
		}
	}

	// Analyze EAPOL Key Message (1, 2, 3, 4)
	// This is slightly complex without full parsing of EAPOL Key,
	// but we can infer or use gopacket eapol layers if available.
	// For now, valid EAPOL is enough to save.
	// To be precise, we want to know if it's Key 1, 2, 3, or 4.
	// We can trust aircrack-ng to parse it if we just dump all EAPOLs.
	// But let's try to identify to logging purposes.

	msgNum := detectKeyMessageNumber(packet, src == bssid)
	if msgNum > 0 {
		session.Captured[msgNum] = true
	}

	// Append packet if we haven't reached the limit
	if len(session.Frames) < maxFramesPerSession {
		session.Frames = append(session.Frames, packet)
	} else {
		// Optional: If we are full, maybe we should drop the oldest?
		// Or strictly keep the first valid handshake?
		// For now, let's just stop adding to avoid memory leak,
		// but update LastUpdate to keep session alive if active.
	}
	session.LastUpdate = time.Now()

	// Check if captured decent set (M1+M2 is min for some cracking, M1-M4 is best)
	// Let's autosave if we have at least 2 different messages or complete
	// hasHandshake := len(session.Captured) >= 2 // Crude heuristic

	// Always save if we see new traffic and have "enough", or periodic?
	// For simplicity, let's write to file every time we update if we have a valid potential handshake.
	// To avoid IO spam, maybe only if we hit a new message type?
	// Or simply: If we have captured M1 and M2, write/overwrite the pcap.

	// Refinement 1: Check if we have M1+M2 (Validation)
	if session.Captured[1] && session.Captured[2] {
		// Refinement 2: Only overwrite if we have MORE data than before or it's the first save
		// This prevents replacing a 4-way with a 2-way in the same session.
		currentCount := len(session.Captured)
		if currentCount > session.SavedCount {
			hm.saveSession(session)
			session.SavedCount = currentCount
			return true
		}
	}
	return false
}

func (hm *HandshakeManager) saveSession(session *HandshakeSession) {
	// Filename: BSSID_ESSID_StationMAC.pcap (Sanitized)
	// This ensures unique files per client (Solution 1)
	essidClean := sanitizeFilename(session.ESSID)
	bssidClean := sanitizeFilename(session.BSSID)
	staClean := sanitizeFilename(session.StationMAC)

	filename := fmt.Sprintf("%s_%s_%s.pcap", bssidClean, essidClean, staClean)
	path := filepath.Join(hm.baseDir, filename)

	f, err := os.Create(path)
	if err != nil {
		log.Printf("Error creating pcap file %s: %v", path, err)
		return
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	// LinkType 127 is DLT_IEEE802_11_RADIO (Radiotap)
	// Or 105 for IEEE802_11. Most gopacket captures include Radiotap layer.
	// Let's assume Radiotap presence.
	w.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio)

	for _, pkt := range session.Frames {
		w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
	}

	// Also dump a Beacon frame if we can find one for context?
	// (Skipping for now to keep simple, but ideal for aircrack-ng)
}

// HasHandshake returns true if a handshake has been captured for the given BSSID.
func (hm *HandshakeManager) HasHandshake(bssid string) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	// Check if any session with this BSSID has captured M1+M2
	for _, session := range hm.sessions {
		if session.BSSID == bssid && session.Captured[1] && session.Captured[2] {
			return true
		}
	}
	return false
}

// Helpers

func getSSIDFromPacket(packet gopacket.Packet) string {
	if beacon := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beacon != nil {
		// Need to parse IEs manually since gopacket might not expose SSID directly on the layer struct easily
		// Actually gopacket's Dot11MgmtBeacon does not have SSID field directly usually, it's in payload.
		// Re-using logic from packet_handler is best, but for now simplest:

		// This is a quick hack. Real robust way is to parse IEs.
		// Assuming we can rely on packet_handler passing the device info?
		// No, this is raw packet.
		// Let's walk layers.
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeDot11InformationElement {
				ie, _ := layer.(*layers.Dot11InformationElement)
				if ie.ID == 0 { // SSID
					return string(ie.Info)
				}
			}
		}
	}
	return ""
}

func detectKeyMessageNumber(packet gopacket.Packet, isFromAP bool) uint8 {
	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return 0
	}
	eapol, ok := eapolLayer.(*layers.EAPOL)
	if !ok || eapol.Type != layers.EAPOLTypeKey {
		return 0
	}

	payload := eapol.LayerPayload()
	if len(payload) < 3 {
		return 0
	}

	// Key Info (2 bytes) at offset 1
	// Using BigEndian as per 802.11 standard for WPA Key Info
	// Byte 0 (of primitive) is bits 8-15? No, wire order is Byte0, Byte1.
	// 802.11 is Little Endian for fields usually, but Key Info is often treated as bitfield.
	// Let's rely on standard parsing: BigEndian Uint16 reads [B0, B1].
	// Bit 8 (Mic) is in B0. Bit 7 (Ack) is in B1.
	// keyInfo := binary.BigEndian.Uint16(payload[1:3])
	// Let's simplify: access bytes directly.
	// B0 = payload[1] (Bits 8-15 if BigEndian? No. Bits 0-7 if Little?)
	// WPA Key Info is Big Endian on wire?
	// Actually most WPA implementations use Big Endian for Key Info.

	keyInfo := binary.BigEndian.Uint16(payload[1:3])

	// Bits (Masks for Uint16):
	// Bit 3: Pairwise (0x0008)
	// Bit 7: Ack      (0x0080)
	// Bit 8: MIC      (0x0100)
	// Bit 9: Secure   (0x0200)

	hasMic := (keyInfo & 0x0100) != 0
	hasAck := (keyInfo & 0x0080) != 0
	// hasSecure := (keyInfo & 0x0200) != 0

	// Logic:
	if !hasMic {
		// Message 1 (No MIC, Ack=1 usually)
		if hasAck {
			return 1
		}
		// Some implementations might vary, but No MIC is strong M1 indicator in 4-way.
		return 1
	}

	// Has MIC
	if hasAck {
		// Message 3 (MIC=1, Ack=1)
		return 3
	}

	// Has MIC, No Ack => M2 or M4
	// Distinguish by Key Data Length?
	// Key Data Len is at offset 93 (2 bytes)
	if len(payload) >= 95 {
		dataLen := binary.BigEndian.Uint16(payload[93:95])
		if dataLen > 0 {
			return 2
		}
		return 4
	}

	// Fallback if short packet (shouldn't happen for valid WPA2)
	// M4 is often short? No, minimal length is usually maintained.
	// Assume M4 if short and matches flags?
	return 4
}

func sanitizeFilename(s string) string {
	// Remove non-alphanumeric
	// Simple mapping
	res := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			res += string(c)
		} else {
			res += "_"
		}
	}
	return res
}
