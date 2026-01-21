package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
)

// IEData represents a raw Information Element generic structure
type IEData struct {
	ID    uint8
	Value []byte
}

// CalculateIEFingerprint generates a consistent hash from Information Elements.
// It skips variable fields (SSID, DS, TIM) to ensure the fingerprint only represents the hardware/driver.
func CalculateIEFingerprint(ies []IEData) string {
	var buffer bytes.Buffer

	for _, ie := range ies {
		// Skip variable IEs that change between requests or channels
		// 0: SSID (Variable scan target)
		// 3: DS Parameter Set (Current Channel)
		// 5: TIM (Traffic Indication Map - AP only, but safe to skip)
		// 221: Vendor Specific (Only skip if it's dynamic, usually keep for fingerprinting)
		if ie.ID == 0 || ie.ID == 3 || ie.ID == 5 {
			continue
		}

		// Write Tag ID and Length
		buffer.WriteByte(ie.ID)
		buffer.WriteByte(byte(len(ie.Value)))
		// Write Value
		buffer.Write(ie.Value)
	}

	if buffer.Len() == 0 {
		return ""
	}

	hash := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(hash[:])
}

// CalculateProbeHash generates a hash from a list of probed SSIDs.
// This is useful for identifying specific users/devices even if they randomize MACs.
func CalculateProbeHash(probedSSIDs []string) string {
	if len(probedSSIDs) == 0 {
		return ""
	}

	// 1. Deduplicate
	unique := make(map[string]bool)
	var list []string
	for _, ssid := range probedSSIDs {
		ssid = strings.TrimSpace(ssid)
		if ssid == "" {
			continue
		}
		if !unique[ssid] {
			unique[ssid] = true
			list = append(list, ssid)
		}
	}

	if len(list) == 0 {
		return ""
	}

	// 2. Sort to ensure determinism
	sort.Strings(list)

	// 3. Hash
	data := strings.Join(list, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ExtractManufacturerFromIEs attempts to find the real manufacturer from WP/P2P IEs.
// Returns empty string if not found.
func ExtractManufacturerFromIEs(ies []IEData) string {
	for _, ie := range ies {
		// Vendor Specific IE (Tag 221)
		if ie.ID == 221 && len(ie.Value) > 4 {
			// Check for Microsoft/WFA OUI (00:50:F2) which is used for WPS
			if ie.Value[0] == 0x00 && ie.Value[1] == 0x50 && ie.Value[2] == 0xF2 {
				// OUI Type 0x04 is WPS
				if ie.Value[3] == 0x04 {
					manuf := parseWPSAttributes(ie.Value[4:])
					if manuf != "" {
						return manuf
					}
				}
			}
		}
	}
	return ""
}

// parseWPSAttributes parses WPS Data Elements to find Manufacturer.
// Manufacturer Attribute ID: 0x1021
func parseWPSAttributes(data []byte) string {
	// TLV parsing
	buf := bytes.NewReader(data)
	for buf.Len() >= 4 {
		var typeID uint16
		var length uint16

		if err := binary.Read(buf, binary.BigEndian, &typeID); err != nil {
			break
		}
		if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
			break
		}

		value := make([]byte, length)
		if _, err := buf.Read(value); err != nil {
			break
		}

		// Check for Manufacturer (0x1021) or Model Name (0x1023)
		// We prefer Manufacturer, but Model Name is also good.
		if typeID == 0x1021 {
			return string(bytes.Trim(value, "\x00"))
		}
	}
	return ""
}
