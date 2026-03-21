package session

import (
	"bytes"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/parser"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/utils"
)

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
	HasReplayCounter bool // Only for WPA 4-Way
	HasWPSActivity   bool // Tracks if this session has WPS frames
	Anonce           []byte

	// Capture quality fields
	LinkType layers.LinkType
}

func NewHandshakeSession(bssid, stationMac, essid string, beacon gopacket.Packet, linkType layers.LinkType) *HandshakeSession {
	return &HandshakeSession{
		BSSID:      bssid,
		StationMAC: stationMac,
		ESSID:      essid,
		Beacon:     beacon,
		Frames:     make([]gopacket.Packet, 0),
		Captured:   make(map[uint8]bool),
		LinkType:   linkType,
		LastUpdate: time.Now(),
	}
}

func (s *HandshakeSession) UpdateESSID(essid string) {
	if s.ESSID == "unknown" || s.ESSID == "" {
		s.ESSID = essid
	}
}

func (s *HandshakeSession) AppendFrame(packet gopacket.Packet, maxFrames int) (bool, bool) {
	// Check for duplicates
	for _, f := range s.Frames {
		if bytes.Equal(f.Data(), packet.Data()) {
			return false, true // isDuplicate=true
		}
	}

	appended := false
	if len(s.Frames) < maxFrames {
		s.Frames = append(s.Frames, packet)
		appended = true
	}
	s.LastUpdate = time.Now()
	return appended, false
}

func (s *HandshakeSession) IsComplete() bool {
	return s.Captured[1] && s.Captured[2] && s.Captured[3] && s.Captured[4]
}

// ProcessEAPOL processes an EAPOL frame and returns whether the session warrants saving.
func (s *HandshakeSession) ProcessEAPOL(packet gopacket.Packet, isWPS bool, wasAppended bool) bool {
	shouldSave := false

	if isWPS {
		s.HasWPSActivity = true
		wpsCount := 0
		for _, f := range s.Frames {
			if utils.IsWPSFrame(f) {
				wpsCount++
			}
		}
		if wpsCount >= 2 {
			shouldSave = true
		}
	} else {
		// Handle WPA 4-Way Handshake
		eapolFrame, err := parser.ParseEAPOLKey(packet)
		if err == nil {
			msgNum := uint8(eapolFrame.DetermineMessageNumber())
			isValid := false

			if msgNum == 1 {
				if s.HasReplayCounter && s.ReplayCounter == eapolFrame.ReplayCounter {
					// Duplicate M1
					isValid = true
				} else {
					// New M1. Reset state.
					s.ReplayCounter = eapolFrame.ReplayCounter
					s.HasReplayCounter = true
					s.Anonce = eapolFrame.Nonce
					s.Captured = make(map[uint8]bool)

					newFrames := make([]gopacket.Packet, 0, len(s.Frames))
					for _, f := range s.Frames {
						if utils.IsWPSFrame(f) || !utils.IsEAPOLKey(f) || bytes.Equal(f.Data(), packet.Data()) {
							newFrames = append(newFrames, f)
						}
					}
					s.Frames = newFrames
					s.SavedCount = 0
					isValid = true
					log.Printf("Captured M1: Starting new session for %s (RC: %d)", s.BSSID, s.ReplayCounter)
				}
			} else if msgNum > 1 {
				isValid = true
				if msgNum == 3 {
					if s.Anonce == nil {
						s.Anonce = eapolFrame.Nonce
						s.ReplayCounter = eapolFrame.ReplayCounter - 1
						s.HasReplayCounter = true
						log.Printf("Recovered context from M3 (ANonce found)")
					} else if !bytes.Equal(s.Anonce, eapolFrame.Nonce) {
						log.Printf("Warning: M3 Anonce mismatch (Target: %s). Rejecting frame.", s.BSSID)
						if wasAppended && len(s.Frames) > 0 {
							s.Frames = s.Frames[:len(s.Frames)-1]
						}
						return false
					}
				}
			}

			if isValid && msgNum > 0 {
				s.Captured[msgNum] = true
			}
		}

		hasWPACapture := s.Captured[2] && (s.Captured[1] || s.Captured[3])
		if hasWPACapture {
			shouldSave = true
		}
	}

	return shouldSave
}

func (s *HandshakeSession) ShouldTriggerSave() bool {
	currentCount := len(s.Frames)
	if currentCount > s.SavedCount || s.SavedCount == 0 {
		return true
	}
	return false
}

// Clone creates a deep copy of the session state for saving to avoid race conditions.
func (s *HandshakeSession) Clone() *HandshakeSession {
	sessionCopy := &HandshakeSession{
		BSSID:          s.BSSID,
		StationMAC:     s.StationMAC,
		ESSID:          s.ESSID,
		LastUpdate:     s.LastUpdate,
		Beacon:         s.Beacon,
		Captured:       make(map[uint8]bool),
		SavedCount:     len(s.Frames),
		LinkType:       s.LinkType,
		HasWPSActivity: s.HasWPSActivity,
		ReplayCounter:  s.ReplayCounter,
		HasReplayCounter: s.HasReplayCounter,
		Anonce:         s.Anonce,
	}
	for k, v := range s.Captured {
		sessionCopy.Captured[k] = v
	}
	sessionCopy.Frames = make([]gopacket.Packet, len(s.Frames))
	copy(sessionCopy.Frames, s.Frames)

	return sessionCopy
}
