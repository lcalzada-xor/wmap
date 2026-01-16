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
	mu           sync.RWMutex
	baseDir      string
	bssidToEssid map[string]string // Kept as map protected by RWMutex for now, but usage optimized
	sessions     map[string]*HandshakeSession
	saveQueue    chan *HandshakeSession
	stopChan     chan struct{}
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
		baseDir:      baseDir,
		bssidToEssid: make(map[string]string),
		sessions:     make(map[string]*HandshakeSession),
		saveQueue:    make(chan *HandshakeSession, 100),
		stopChan:     make(chan struct{}),
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

	// 1. Process Beacons to learn ESSIDs
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		bssid := dot11.Address3.String()
		if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
			// Extract SSID from IEs
			essid := getSSIDFromPacket(packet)
			if essid != "" && essid != "<HIDDEN>" {
				// Optimization: Check with Read Lock first
				hm.mu.RLock()
				existing, ok := hm.bssidToEssid[bssid]
				hm.mu.RUnlock()

				if !ok || existing != essid {
					hm.mu.Lock()
					hm.bssidToEssid[bssid] = essid
					hm.mu.Unlock()
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
	// Address3 = BSSID

	// Determine addresses based on DS flags
	// Address1 = Recipient (RA) / DA
	// Address2 = Transmitter (TA) / SA
	// Address3 = BSSID (usually)
	//
	// ToDS=0, FromDS=0: Mgmt/AdHoc. BSSID=Addr3. SA=Addr2. DA=Addr1.
	// ToDS=0, FromDS=1: Downlink (AP->STA). BSSID=Addr2. DA=Addr1. SA=Addr3 (Src).
	// ToDS=1, FromDS=0: Uplink (STA->AP). BSSID=Addr1. SA=Addr2. DA=Addr3 (Dst).
	// ToDS=1, FromDS=1: WDS. BSSID not clearly defined single field.

	var bssid, stationMac string
	toDS := dot11.Flags.ToDS()
	fromDS := dot11.Flags.FromDS()

	if !toDS && !fromDS {
		// AdHoc / Mgmt
		bssid = dot11.Address3.String()
		// EAPOL in AdHoc? Rare.
		// If src==bssid logic applies here.
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
		// WDS (Mesh) - ToDS=1, FromDS=1
		// RA=Addr1, TA=Addr2.
		// Usually EAPOL is link-local, so Sender/Receiver are the peers.
		// Let's assume TA is one peer, RA is the other.
		// Which one is Authenticator (BSSID role)? Hard to say without more context.
		// Let's use Addr2 as Source/Authenticator candidate?
		// Skipping WDS for now or defaulting to safe fallback:
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

	// Analyze EAPOL Key Message (1, 2, 3, 4)
	eapolFrame, err := ParseEAPOLKey(packet)
	if err == nil {
		msgNum := uint8(eapolFrame.DetermineMessageNumber())

		isValid := false

		// Sequence Validation Logic
		if msgNum == 1 {
			// M1: Start of a new sequence (mostly).
			// Check if it is a retransmission of the CURRENT session M1
			// RC=0 Fix: Use HasReplayCounter flag instead of check > 0
			if session.HasReplayCounter && session.ReplayCounter == eapolFrame.ReplayCounter {
				// Duplicate M1 (Retransmission).
				// Do NOT reset the session. We might already have M2.
				// Just mark as valid duplicate.
				isValid = true
				log.Printf("Duplicate M1 ignored (RC: %d)", session.ReplayCounter)
			} else {
				// New M1 (Different RC or first one). Reset session.
				session.ReplayCounter = eapolFrame.ReplayCounter
				session.HasReplayCounter = true
				session.Anonce = eapolFrame.Nonce
				// Clear captured map
				session.Captured = make(map[uint8]bool)
				session.Frames = make([]gopacket.Packet, 0)
				session.SavedCount = 0 // Fix: Reset saved count for new handshake
				isValid = true
				log.Printf("Captured M1: Starting new session for %s (RC: %d)", session.BSSID, session.ReplayCounter)
			}
		} else if msgNum > 1 {
			// M2, M3, M4: Must match existing session context
			if session.Anonce == nil {
				// We don't have M1 context.
				// Can we accept M2 without M1?
				// For cracking, we NEED M1 (Anonce) and M2 (Snonce+MIC).
				// So M2 without M1 is useless.
				// M3/M4 without matches might be useless too.
				// OR we might have missed M1 but stored others.
				// Let's be strict: Require M1 context for now?
				// "Frankenstein" prevention means we shouldn't mix.
				// If we receive "orphan" M2, we ignore it?
				// Yes, for robust capture, we want M1-M2 paired.
				log.Printf("Discarding M%d: No active session (M1 missing)", msgNum)
				isValid = false
			} else {
				// Validate Replay Counter
				expectedRC := session.ReplayCounter
				if msgNum == 3 || msgNum == 4 {
					expectedRC = session.ReplayCounter + 1
				}

				// Allow retransmissions (==) for M3/M4 if we already saw them?
				// Standard:
				// M1: RC=N
				// M2: RC=N
				// M3: RC=N+1
				// M4: RC=N+1

				if msgNum == 2 {
					if eapolFrame.ReplayCounter == expectedRC {
						isValid = true
					} else {
						log.Printf("Invalid M2: RC %d != Expected %d", eapolFrame.ReplayCounter, expectedRC)
					}
				} else if msgNum == 3 {
					// M3 should have RC+1
					// Also Anonce should match? Usually yes.
					if bytes.Equal(eapolFrame.Nonce, session.Anonce) {
						if eapolFrame.ReplayCounter == expectedRC {
							isValid = true
							// Update Session RC to N+1? No, base is still N from M1.
							// But for M4 validation, we expect N+1.
							// Let's keep base as M1's RC.
						} else if eapolFrame.ReplayCounter == session.ReplayCounter {
							// Relaxed Check: Some APs don't increment RC for M3?
							// If Anonce matches, it's very likely the correct session.
							// Warn but accept.
							log.Printf("Warning: M3 RC %d equals M1 RC (Expected %d). Allowing due to Anonce match.", eapolFrame.ReplayCounter, expectedRC)
							isValid = true
						} else {
							// But standard says +1. Strict mode: enforce +1.
							log.Printf("Invalid M3: RC %d != Expected %d", eapolFrame.ReplayCounter, expectedRC)
						}
					} else {
						log.Printf("Invalid M3: Anonce mismatch (AP reset?)")
						// Implicitly, this might be a new M1 disguised? No, M1 has different flags.
						// This is likely a mixed session. Drop it.
					}
				} else if msgNum == 4 {
					if eapolFrame.ReplayCounter == expectedRC {
						isValid = true
					}
				}
			}
		}

		if isValid && msgNum > 0 {
			session.Captured[msgNum] = true

			// Append packet if we haven't reached the limit
			// Only append if VALID
			if len(session.Frames) < maxFramesPerSession {
				session.Frames = append(session.Frames, packet)
			}
		}
	} else {
		// Not EAPOL key or parse error
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
			// Async Save
			// Deep copy session for safety in async worker
			sessionCopy := &HandshakeSession{
				BSSID:      session.BSSID,
				StationMAC: session.StationMAC,
				ESSID:      session.ESSID,
				LastUpdate: session.LastUpdate,
				Captured:   make(map[uint8]bool),
				SavedCount: currentCount, // Update count in copy not relevant, but good for completeness
			}
			// Copy map
			for k, v := range session.Captured {
				sessionCopy.Captured[k] = v
			}
			// Copy frames
			sessionCopy.Frames = make([]gopacket.Packet, len(session.Frames))
			copy(sessionCopy.Frames, session.Frames)

			// Update main session saved count
			session.SavedCount = currentCount

			// Send to queue (non-blocking if full to avoid stalling main capture)
			select {
			case hm.saveQueue <- sessionCopy:
			default:
				log.Printf("Warning: Handshake save queue full, dropping save for %s", session.BSSID)
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
		// Optimization: Try to parse generic payload first (faster)
		if ssid := ie.ParseSSID(beacon.LayerPayload()); ssid != "" {
			return ssid
		}

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
