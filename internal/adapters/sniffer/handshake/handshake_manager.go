package handshake

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
)

const (
	defaultSessionTimeout    = 5 * time.Minute
	incompleteSessionTimeout = 60 * time.Second
	cleanupInterval          = 1 * time.Minute
	maxFramesPerSession      = 20
)

// HandshakeManager handles the capture and storage of WPA/WPA2 handshakes.
type HandshakeManager struct {
	mu            sync.RWMutex
	baseDir       string
	bssidToEssid  map[string]string          // Kept as map protected by RWMutex for now, but usage optimized
	bssidToBeacon map[string]gopacket.Packet // BSSID -> Beacon Packet (Cache)
	sessions      map[string]*HandshakeSession
	saveQueue     chan *HandshakeSession
	stopChan      chan struct{}
}

// HandshakeSession represents a capture session for a specific BSSID+Station pair.
type HandshakeSession struct {
	BSSID      string
	StationMAC string
	ESSID      string
	Frames     []gopacket.Packet
	Beacon     gopacket.Packet // Best beacon frame, required for aircrack-ng ESSID detection
	LastUpdate time.Time
	Captured   map[uint8]bool // Tracks 1=M1, 2=M2, 3=M3, 4=M4
	SavedCount int            // How many unique messages were in the last saved file

	// Validation fields
	ReplayCounter    uint64
	HasReplayCounter bool
	Anonce           []byte
}

// NewHandshakeManager creates a new manager.
func NewHandshakeManager(baseDir string) *HandshakeManager {
	// Ensure directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		log.Printf("ERROR: Could not create handshake capture dir: %v", err)
	}

	hm := &HandshakeManager{
		baseDir:       baseDir,
		bssidToEssid:  make(map[string]string),
		bssidToBeacon: make(map[string]gopacket.Packet),
		sessions:      make(map[string]*HandshakeSession),
		saveQueue:     make(chan *HandshakeSession, 100),
		stopChan:      make(chan struct{}),
	}

	// Start cleanup routine
	go hm.startCleanupRoutine()
	// Start save routine
	go hm.saveLoop()

	return hm
}

// Close stops background routines.
func (hm *HandshakeManager) Close() {
	close(hm.stopChan)
}

func (hm *HandshakeManager) startCleanupRoutine() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			hm.CleanupSessions()
		case <-hm.stopChan:
			return
		}
	}
}

func (hm *HandshakeManager) saveLoop() {
	for {
		select {
		case session := <-hm.saveQueue:
			hm.saveSession(session)
		case <-hm.stopChan:
			return
		}
	}
}

// CleanupSessions removes sessions that haven't been updated recently.
func (hm *HandshakeManager) CleanupSessions() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	now := time.Now()
	for key, session := range hm.sessions {
		// Determine timeout based on state
		timeout := defaultSessionTimeout
		isComplete := session.Captured[1] && session.Captured[2] && session.Captured[3] && session.Captured[4]

		if !isComplete {
			timeout = incompleteSessionTimeout
		}

		if now.Sub(session.LastUpdate) > timeout {
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

	// 1. Process Beacons to learn ESSIDs and store Beacon packet
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		bssid := dot11.Address3.String()
		if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
			// Extract SSID from IEs
			essid := getSSIDFromPacket(packet)
			if essid != "" && essid != "<HIDDEN>" {
				hm.mu.Lock()
				defer hm.mu.Unlock()

				// Update BSSID -> ESSID map
				hm.bssidToEssid[bssid] = essid
				// Update Beacon Cache
				hm.bssidToBeacon[bssid] = packet
				log.Printf("DEBUG: Stored beacon for BSSID %s (SSID: %s)", bssid, essid)

				// Check if we have active sessions for this BSSID without a beacon or with a hidden one
				// Since we don't index sessions by BSSID easily (key is BSSID_STA), iterating is okayish or we wait for next EAPOL.
				// But we should store this beacon for future sessions or current ones.
				// Since we can't easily find all sessions for a BSSID without map iteration, let's just store it in a separate cache if needed?
				// Actually, let's just iteration. "sessions" map is usually small.
				for _, session := range hm.sessions {
					if session.BSSID == bssid {
						// Store this beacon if we don't have one, or if ours is better (not implemented yet, just overwrite)
						if session.Beacon == nil {
							session.Beacon = packet
							session.ESSID = essid // Ensure session has correct ESSID
						}
					}
				}
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
	// Address3 = BSSID (usually)

	// Determine addresses based on DS flags
	var bssid, stationMac string
	toDS := dot11.Flags.ToDS()
	fromDS := dot11.Flags.FromDS()

	if !toDS && !fromDS {
		// AdHoc / Mgmt
		bssid = dot11.Address3.String()
		if dot11.Address2.String() == bssid {
			stationMac = dot11.Address1.String()
		} else {
			stationMac = dot11.Address2.String()
		}
	} else if !toDS && fromDS {
		// AP -> Station (Downlink)
		// RA=Addr1(Station), TA=Addr2(BSSID), SA=Addr3(Src)
		bssid = dot11.Address2.String()
		stationMac = dot11.Address1.String()
	} else if toDS && !fromDS {
		// Station -> AP (Uplink)
		// RA=Addr1(BSSID), TA=Addr2(Station), DA=Addr3(Dst)
		bssid = dot11.Address1.String()
		stationMac = dot11.Address2.String()
	} else {
		// WDS or unknown - skip
		return false
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
		// Look up cached beacon
		var beacon gopacket.Packet
		if cached, ok := hm.bssidToBeacon[bssid]; ok {
			beacon = cached
		}

		session = &HandshakeSession{
			BSSID:      bssid,
			StationMAC: stationMac,
			ESSID:      essid,
			Beacon:     beacon, // Seed with cached beacon
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
	eapolFrame, err := ParseEAPOLKey(packet)
	if err == nil {
		msgNum := uint8(eapolFrame.DetermineMessageNumber())
		isValid := false

		if msgNum == 1 {
			// M1: Start of a new sequence
			// Check if it is a retransmission of the CURRENT session M1
			if session.HasReplayCounter && session.ReplayCounter == eapolFrame.ReplayCounter {
				// Duplicate M1
				isValid = true
			} else {
				// New M1. Reset session.
				session.ReplayCounter = eapolFrame.ReplayCounter
				session.HasReplayCounter = true
				session.Anonce = eapolFrame.Nonce
				session.Captured = make(map[uint8]bool)
				session.Frames = make([]gopacket.Packet, 0)
				session.SavedCount = 0
				isValid = true
				log.Printf("Captured M1: Starting new session for %s (RC: %d)", session.BSSID, session.ReplayCounter)
			}
		} else if msgNum > 1 {
			// M2, M3, M4
			isValid = true // Assume valid tentatively to allow mid-stream capture

			// Recovery Strategy: If we missed M1, we can recover info from M3
			if msgNum == 3 && session.Anonce == nil {
				// M3 cointains the ANonce!
				session.Anonce = eapolFrame.Nonce
				// Best effort Replay Counter sync:
				// M3 RC should be N+1. So Base N = RC - 1.
				session.ReplayCounter = eapolFrame.ReplayCounter - 1
				session.HasReplayCounter = true
				log.Printf("Recovered context from M3 (ANonce found)")
			}

			// If we still lack context (e.g. only M2 seen so far), strictly speaking we can't validate RC/Nonce.
			// But we should STORE it, in case M3 comes later to complete the puzzle.
			if session.Anonce == nil {
				// We have M2 or M4 but no M1/M3 yet.
				// Store it. Aircrack-ng can sometimes use loose frames or we might get M1/M3 later.
				log.Printf("Captured M%d without context (waiting for M1/M3)", msgNum)
			} else {
				// We have context, perform validation if possible
				expectedRC := session.ReplayCounter
				if msgNum == 3 || msgNum == 4 {
					expectedRC = session.ReplayCounter + 1
				}

				if msgNum == 3 {
					// Validate Anonce if we didn't just learn it
					if !bytes.Equal(eapolFrame.Nonce, session.Anonce) {
						// This M3 belongs to a different session?
						// Or AP changed header.
						log.Printf("Warning: M3 Anonce mismatch. Resetting session to new context.")

						// Reset complete session to avoid Frankenstein (mixing old M1/M2 with new M3)
						session.Captured = make(map[uint8]bool)
						session.Frames = make([]gopacket.Packet, 0)
						session.SavedCount = 0

						// Initialize with M3 info
						session.Anonce = eapolFrame.Nonce
						// Best effort RC sync
						session.ReplayCounter = eapolFrame.ReplayCounter - 1
						session.HasReplayCounter = true
					} else {
						// Validate RC if possible (strict or relaxed)
						if eapolFrame.ReplayCounter != expectedRC {
							log.Printf("Note: M3 RC %d != Expected %d", eapolFrame.ReplayCounter, expectedRC)
						}
					}
				} else if msgNum == 2 {
					// M2 RC should match M1 RC
					if eapolFrame.ReplayCounter != session.ReplayCounter {
						log.Printf("Note: M2 RC %d != Session RC %d (Likely specific implementation or missed M1)", eapolFrame.ReplayCounter, session.ReplayCounter)
						// Accept anyway
					}
				} else if msgNum == 4 {
					if eapolFrame.ReplayCounter != expectedRC {
						log.Printf("Note: M4 RC %d != Expected %d", eapolFrame.ReplayCounter, expectedRC)
					}
				}
			}
		}

		if isValid && msgNum > 0 {
			// MIC Validation
			if eapolFrame.HasMIC && eapolFrame.IsMICZero() {
				log.Printf("Warning: Dropping frame M%d with zeroed MIC (invalid)", msgNum)
				isValid = false
			}
		}

		if isValid && msgNum > 0 {
			session.Captured[msgNum] = true
			if len(session.Frames) < maxFramesPerSession {
				session.Frames = append(session.Frames, packet)
			}
		}
	}

	session.LastUpdate = time.Now()

	// Robust Handshake Check:
	// We have a usable handshake if we have:
	// 1. ANonce (From M1 or M3) AND SNonce (From M2)
	// 2. Ideally MICs valid (can't check easily here)
	// Simple check: do we have M2 AND (M1 OR M3)?
	// M2 provides SNonce + MIC. M1/M3 provides ANonce.
	hasNecessaryComponents := session.Captured[2] && (session.Captured[1] || session.Captured[3])

	// Trigger Save if we have necessary components
	if hasNecessaryComponents {
		currentCount := len(session.Captured)
		if currentCount > session.SavedCount || session.SavedCount == 0 {
			sessionCopy := &HandshakeSession{
				BSSID:      session.BSSID,
				StationMAC: session.StationMAC,
				ESSID:      session.ESSID,
				LastUpdate: session.LastUpdate,
				Beacon:     session.Beacon, // Copy the beacon
				Captured:   make(map[uint8]bool),
				SavedCount: currentCount,
			}
			for k, v := range session.Captured {
				sessionCopy.Captured[k] = v
			}
			sessionCopy.Frames = make([]gopacket.Packet, len(session.Frames))
			copy(sessionCopy.Frames, session.Frames)

			session.SavedCount = currentCount

			select {
			case hm.saveQueue <- sessionCopy:
			default:
				log.Printf("Warning: Handshake save queue full")
			}
			return true
		}
	}

	return false
}

// RegisterNetwork manually registers an ESSID for a BSSID (useful for testing or seeding)
func (hm *HandshakeManager) RegisterNetwork(bssid, essid string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.bssidToEssid[bssid] = essid
}

func (hm *HandshakeManager) saveSession(session *HandshakeSession) {
	// Filename: BSSID_ESSID_StationMAC.pcap (Sanitized)
	// This ensures unique files per client (Solution 1)
	essidClean := sanitizeFilename(session.ESSID)
	bssidClean := sanitizeFilename(session.BSSID)
	staClean := sanitizeFilename(session.StationMAC)

	filename := fmt.Sprintf("%s_%s_%s.pcap", bssidClean, essidClean, staClean)
	path := filepath.Join(hm.baseDir, filename)

	log.Printf("DEBUG: Attempting to save session to %s", path)

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

	// Write Beacon First (Critical for aircrack-ng)
	if session.Beacon != nil {
		if err := w.WritePacket(session.Beacon.Metadata().CaptureInfo, session.Beacon.Data()); err != nil {
			log.Printf("Error writing beacon to pcap: %v", err)
		}
	}

	for _, pkt := range session.Frames {
		if err := w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
			log.Printf("Error writing packet to pcap: %v", err)
		}
	}
	log.Printf("DEBUG: Successfully saved session to %s", path)
}

// SavePMKID saves a single packet containing a PMKID to a pcap file.
func (hm *HandshakeManager) SavePMKID(packet gopacket.Packet, bssid, essid string) {
	// Ensure we have a valid ESSID for filename
	if essid == "" {
		hm.mu.RLock()
		if val, ok := hm.bssidToEssid[bssid]; ok {
			essid = val
		} else {
			essid = "unknown"
		}
		hm.mu.RUnlock()
	}

	// Filename: BSSID_ESSID_PMKID.pcap
	essidClean := sanitizeFilename(essid)
	bssidClean := sanitizeFilename(bssid)
	filename := fmt.Sprintf("%s_%s_PMKID.pcap", bssidClean, essidClean)
	path := filepath.Join(hm.baseDir, filename)

	// Check if already exists to avoid spamming I/O?
	// For now, overwrite or skip. Let's overwrite to ensure latest capture.
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Error creating PMKID pcap file %s: %v", path, err)
		return
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio)

	// Try to find a beacon to include
	hm.mu.RLock()
	beacon := hm.bssidToBeacon[bssid]
	hm.mu.RUnlock()

	if beacon != nil {
		w.WritePacket(beacon.Metadata().CaptureInfo, beacon.Data())
	}

	w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	log.Printf("Saved PMKID capture: %s", filename)
}

// HasHandshake returns true if a handshake has been captured for the given BSSID.
func (hm *HandshakeManager) HasHandshake(bssid string) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	// Check if any session with this BSSID has captured M2 and (M1 or M3)
	for _, session := range hm.sessions {
		if session.BSSID == bssid && session.Captured[2] && (session.Captured[1] || session.Captured[3]) {
			return true
		}
	}
	return false
}

// Helpers

func getSSIDFromPacket(packet gopacket.Packet) string {
	if beacon := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beacon != nil {
		// Optimization: Try to parse generic payload first (faster)
		payload := beacon.LayerPayload()
		ssid := ie.ParseSSID(payload)
		if !ssid.Hidden {
			return ssid.Value
		}
		log.Printf("DEBUG: ParseSSID failed (Hidden=%v) for payload len %d: %x", ssid.Hidden, len(payload), payload)

		// Fallback: Walk layers if gopacket parsed them individually
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
