package parser

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// handleHandshakeCapture checks for Handshakes, PMKID, and M1 anomalies
func (h *PacketHandler) handleHandshakeCapture(packet gopacket.Packet) (bool, *domain.Alert) {
	if h.HandshakeManager == nil {
		return false, nil
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return false, nil
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return false, nil
	}

	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	var eapol *layers.EAPOL
	isEAPOLKey := false
	if eapolLayer != nil {
		e, ok := eapolLayer.(*layers.EAPOL)
		if ok && e.Type == layers.EAPOLTypeKey {
			eapol = e
			isEAPOLKey = true
		}
	}

	isMgmt := isRelevantMgmt(dot11)

	if !isEAPOLKey && !isMgmt {
		return false, nil
	}

	if h.PauseCallback != nil {
		h.PauseCallback(1500 * time.Millisecond)
	}

	saved := h.HandshakeManager.ProcessFrame(packet)
	if saved {
		if h.PauseCallback != nil {
			h.PauseCallback(1500 * time.Millisecond)
		}
		bssid := dot11.Address3.String()

		alert := &domain.Alert{
			Type:          "HANDSHAKE_CAPTURED",
			Subtype:       "WPA_HANDSHAKE",
			Severity:      "Warning",
			DeviceMAC:     dot11.Address2.String(),
			TargetMAC:     dot11.Address1.String(),
			Timestamp:     time.Now(),
			Message:       "WPA Handshake Captured",
			Details:       fmt.Sprintf("BSSID: %s", bssid),
			HandshakeFile: h.HandshakeManager.GetHandshakeFile(bssid),
		}
		return true, alert
	}

	if isEAPOLKey && eapol != nil {
		// Passive PMKID Detection
		if detected := h.detectPMKID(packet, dot11, eapol); detected {
			alert := &domain.Alert{
				Type:      "ANOMALY",
				Subtype:   "VULNERABILITY_DETECTED",
				DeviceMAC: dot11.Address3.String(), // BSSID is the vulnerable entity
				Timestamp: time.Now(),
				Message:   "Vulnerability Detected: PMKID Exposure",
				Details:   "Device is broadcasting PMKID in EAPOL M1. Evidence: PMKID IE present",
				Severity:  "High", // Using string severity for Alert
			}
			return true, alert
		}

		// Passive M1 Analysis (Nonce Randomness)
		if alert := h.analyzeM1(dot11, eapol); alert != nil {
			return true, alert
		}
	}

	return false, nil
}

func isRelevantMgmt(dot11 *layers.Dot11) bool {
	return dot11.Type == layers.Dot11TypeMgmtAuthentication ||
		dot11.Type == layers.Dot11TypeMgmtAssociationReq ||
		dot11.Type == layers.Dot11TypeMgmtReassociationReq
}

func (h *PacketHandler) detectPMKID(packet gopacket.Packet, dot11 *layers.Dot11, eapol *layers.EAPOL) bool {
	payload := eapol.LayerPayload()
	// EAPOL Key Frame header minimum size (to reach Key Data Length) is 95 bytes.
	// 1 (Descriptor Type) + 2 (Key Info) + 2 (Key Len) + 8 (Replay Counter) +
	// 32 (Nonce) + 16 (IV) + 8 (RSC) + 8 (ID) + 16 (MIC) = 93 bytes basic header.
	// Key Data Length (2 bytes) follows at offset 93.
	if len(payload) < 95 {
		return false
	}

	// Check for PMKID in Key Data (after offset 95)
	keyDataLen := int(payload[93])<<8 | int(payload[94])
	if keyDataLen == 0 || 95+keyDataLen > len(payload) {
		return false
	}

	keyData := payload[95 : 95+keyDataLen]

	if ie.ParsePMKID(keyData) {
		// Save PMKID Packet
		if h.HandshakeManager != nil {
			h.HandshakeManager.SavePMKID(packet, dot11.Address3.String(), "")
		}
		return true
	}

	return false
}

func (h *PacketHandler) analyzeM1(dot11 *layers.Dot11, eapol *layers.EAPOL) *domain.Alert {
	payload := eapol.LayerPayload()
	
	// EAPOL Key Frame Check
	// Descriptor Type (1 byte) | Key Info (2) | Key Len (2) | Replay Counter (8) | Key Nonce (32)
	// Offset for Nonce: 1 + 2 + 2 + 8 = 13
	if len(payload) < 13+32 {
		return nil
	}

	// Verify it's an M1 message
	// Key Info is at offset 1 (2 bytes). It is big-endian typically in the frame for these bits.
	// Key Ack is bit 7 (in the 16 bit field), Key MIC is bit 8.
	// payload[1] contains bits 8-15, payload[2] contains bits 0-7.
	// Key Ack (bit 7) is in payload[2] (0x80)
	// Key MIC (bit 8) is in payload[1] (0x01)
	keyAckSet := (payload[2] & 0x80) != 0
	keyMICSet := (payload[1] & 0x01) != 0

	// Also it MUST come from AP
	if !dot11.Flags.FromDS() {
		return nil // Client -> AP
	}

	// For M1: Key Ack IS set, Key MIC is NOT set
	if !keyAckSet || keyMICSet {
		return nil
	}

	nonce := payload[13 : 13+32]

	// 1. Zero Nonce Check
	allZero := true
	for _, b := range nonce {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		return &domain.Alert{
			Type:      "ANOMALY",
			Subtype:   "WEAK_CRYPTO_ZERO_NONCE",
			Severity:  "Critical",
			Message:   "Critical Crypto Flaw: AP generating Zero Nonce in Handshake",
			Details:   "BSSID: " + dot11.Address3.String(),
			DeviceMAC: dot11.Address3.String(),
			Timestamp: time.Now(),
		}
	}

	// 2. Repeating Pattern Check (e.g., all 0xAA)
	first := nonce[0]
	allSame := true
	for _, b := range nonce {
		if b != first {
			allSame = false
			break
		}
	}
	if allSame {
		return &domain.Alert{
			Type:      "ANOMALY",
			Subtype:   "WEAK_CRYPTO_BAD_RNG",
			Severity:  "High",
			Message:   "Weak RNG Detected: Nonce contains repeating bytes",
			Details:   fmt.Sprintf("Pattern: %02x, BSSID: %s", first, dot11.Address3.String()),
			DeviceMAC: dot11.Address3.String(),
			Timestamp: time.Now(),
		}
	}

	return nil
}

func isEAPOLKey(packet gopacket.Packet) bool {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		if eapol, ok := eapolLayer.(*layers.EAPOL); ok {
			return eapol.Type == layers.EAPOLTypeKey
		}
	}
	return false
}
