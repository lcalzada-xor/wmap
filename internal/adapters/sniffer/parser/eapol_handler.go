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
	if h.HandshakeManager != nil {
		// Aggressive Pause: If we see EAPOL, pause IMMEDIATELY
		if isEAPOLKey(packet) {
			if h.PauseCallback != nil {
				h.PauseCallback(5 * time.Second)
			}
		}

		saved := h.HandshakeManager.ProcessFrame(packet)
		if saved {
			// Trigger Reactive Hopping: Pause to capture more frames
			if h.PauseCallback != nil {
				h.PauseCallback(5 * time.Second)
			}

			dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
			bssid := dot11.Address3.String()

			alert := &domain.Alert{
				Type:      "HANDSHAKE_CAPTURED",
				Subtype:   "WPA_HANDSHAKE",
				DeviceMAC: dot11.Address2.String(), // Source (likely Station or AP)
				TargetMAC: dot11.Address1.String(), // Dest
				Timestamp: time.Now(),
				Message:   "WPA Handshake Captured",
				Details:   fmt.Sprintf("BSSID: %s", bssid),
			}
			return true, alert
		}

		// Passive PMKID Detection
		if isEAPOLKey(packet) {
			if vuln := h.detectPMKID(packet); vuln != nil {
				dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
				alert := &domain.Alert{
					Type:      domain.AlertAnomaly,
					Subtype:   "VULNERABILITY_DETECTED",
					DeviceMAC: dot11.Address3.String(), // BSSID is the vulnerable entity
					Timestamp: time.Now(),
					Message:   "Vulnerability Detected: PMKID Exposure",
					Details:   fmt.Sprintf("Device is broadcasting PMKID in EAPOL M1. Evidence: %s", vuln.Evidence[0]),
					Severity:  domain.SeverityHigh, // Using string severity for Alert
				}
				return true, alert
			}
		}

		// Passive M1 Analysis (Nonce Randomness)
		if isEAPOLKey(packet) {
			if alert := h.analyzeM1(packet); alert != nil {
				return true, alert
			}
		}
	}
	return false, nil
}

func isEAPOLKey(packet gopacket.Packet) bool {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		if eapol, ok := eapolLayer.(*layers.EAPOL); ok {
			return eapol.Type == layers.EAPOLTypeKey
		}
	}
	return false
}

func (h *PacketHandler) detectPMKID(packet gopacket.Packet) *domain.VulnerabilityTag {
	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return nil
	}

	eapol, ok := eapolLayer.(*layers.EAPOL)
	if !ok || eapol.Type != layers.EAPOLTypeKey {
		return nil
	}

	// Parse EAPOL Key frame
	payload := eapol.LayerPayload()
	if len(payload) < 95 {
		return nil
	}

	// Check for PMKID in Key Data (after offset 95)
	keyDataLen := int(payload[93])<<8 | int(payload[94])
	if keyDataLen == 0 || 95+keyDataLen > len(payload) {
		return nil
	}

	keyData := payload[95 : 95+keyDataLen]

	if ie.ParsePMKID(keyData) {
		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		if dot11Layer == nil {
			return nil
		}
		dot11 := dot11Layer.(*layers.Dot11)

		// Save PMKID Packet
		if h.HandshakeManager != nil {
			h.HandshakeManager.SavePMKID(packet, dot11.Address3.String(), "")
		}

		return &domain.VulnerabilityTag{
			Name:        "PMKID",
			Severity:    domain.VulnSeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Evidence:    []string{"PMKID present in EAPOL M1", "BSSID: " + dot11.Address3.String()},
			DetectedAt:  time.Now(),
			Category:    "protocol",
			Description: "PMKID exposed - allows offline PSK cracking without handshake",
			Mitigation:  "Disable PMKID caching or use WPA3",
		}
	}

	return nil
}

func (h *PacketHandler) analyzeM1(packet gopacket.Packet) *domain.Alert {
	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return nil
	}

	eapol, ok := eapolLayer.(*layers.EAPOL)
	if !ok || eapol.Type != layers.EAPOLTypeKey {
		return nil
	}

	payload := eapol.LayerPayload()
	// EAPOL Key Frame Check
	// Descriptor Type (1 byte) | Key Info (2) | Key Len (2) | Replay Counter (8) | Key Nonce (32)
	// Offset for Nonce: 1 + 2 + 2 + 8 = 13
	if len(payload) < 13+32 {
		return nil
	}

	// Verify it's M1 (Key Ack set, Key MIC NOT set)
	// Key Info is at offset 1 (2 bytes). Big Endian.
	// Bit 7: Key Ack (check if set). Bit 8: Key MIC (check if NOT set).
	// 0x0080 = Key Ack. 0x0100 = Key MIC. (Depends on endianness in packet vs parsing)
	// Actually G1/G2 bits differ. Assuming 802.11 endianness.
	// Let's rely on FromDS check for AP direction + having Nonce.

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil
	}
	dot11 := dot11Layer.(*layers.Dot11)

	if !dot11.Flags.FromDS() {
		return nil // Client -> AP
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
			Type:      domain.AlertAnomaly,
			Subtype:   "WEAK_CRYPTO_ZERO_NONCE",
			Severity:  domain.SeverityCritical,
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
			Type:      domain.AlertAnomaly,
			Subtype:   "WEAK_CRYPTO_BAD_RNG",
			Severity:  domain.SeverityHigh,
			Message:   "Weak RNG Detected: Nonce contains repeating bytes",
			Details:   fmt.Sprintf("Pattern: %02x, BSSID: %s", first, dot11.Address3.String()),
			DeviceMAC: dot11.Address3.String(),
			Timestamp: time.Now(),
		}
	}

	return nil
}
