package ie

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// RSNInfo represents the parsed RSN Information Element
type RSNInfo struct {
	Version         uint16
	GroupCipher     string
	PairwiseCiphers []string
	AKMSuites       []string
	Capabilities    RSNCapabilities
	PMKIDs          []string
	GroupMgmtCipher string
}

// RSNCapabilities represents the capabilities field of RSN IE
type RSNCapabilities struct {
	PreAuth          bool
	NoPairwise       bool
	PTKSAReplayCount uint8
	GTKSAReplayCount uint8
	MFPRequired      bool
	MFPCapable       bool
	JointMultiBand   bool // Bit 8
	PeerKeyEnabled   bool // Bit 9
	OCVC             bool // Bit 10
}

// ParseRSN parses IE 48 (RSN Information Element)
func ParseRSN(data []byte) (*RSNInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("RSN IE too short")
	}

	rsn := &RSNInfo{}
	offset := 0

	// Version (2 bytes)
	rsn.Version = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Group Cipher Suite (4 bytes: OUI + Type)
	if offset+4 <= len(data) {
		rsn.GroupCipher = parseCipherSuite(data[offset : offset+4])
		offset += 4
	}

	// Pairwise Cipher Suite Count + List
	if offset+2 <= len(data) {
		count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		for i := 0; i < count; i++ {
			if offset+4 > len(data) {
				return rsn, nil
			}
			rsn.PairwiseCiphers = append(rsn.PairwiseCiphers, parseCipherSuite(data[offset:offset+4]))
			offset += 4
		}
	}

	// AKM Suite Count + List
	if offset+2 <= len(data) {
		count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		for i := 0; i < count; i++ {
			if offset+4 > len(data) {
				return rsn, nil
			}
			rsn.AKMSuites = append(rsn.AKMSuites, parseAKMSuite(data[offset:offset+4]))
			offset += 4
		}
	}

	// RSN Capabilities (2 bytes)
	if offset+2 <= len(data) {
		caps := binary.LittleEndian.Uint16(data[offset : offset+2])
		rsn.Capabilities = parseRSNCapabilities(caps)
		offset += 2
	}

	// PMKID Count + List
	if offset+2 <= len(data) {
		count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		for i := 0; i < count; i++ {
			if offset+16 > len(data) {
				return rsn, nil
			}
			pmkid := fmt.Sprintf("%x", data[offset:offset+16])
			rsn.PMKIDs = append(rsn.PMKIDs, pmkid)
			offset += 16
		}
	}

	// Group Management Cipher Suite (4 bytes)
	if offset+4 <= len(data) {
		rsn.GroupMgmtCipher = parseCipherSuite(data[offset : offset+4])
		offset += 4
	}

	return rsn, nil
}

func parseCipherSuite(data []byte) string {
	if len(data) < 4 {
		return "UNKNOWN"
	}

	// Check if OUI is standard WiFi Alliance (00-0F-AC)
	isStandard := bytes.Equal(data[0:3], OUIWiFiAlliance)
	cipherType := data[3]

	if !isStandard {
		return fmt.Sprintf("VENDOR(%02x%02x%02x:%d)", data[0], data[1], data[2], cipherType)
	}

	switch cipherType {
	case 0:
		return "USE-GROUP"
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP-128" // AES
	case 5:
		return "WEP-104"
	case 6:
		return "BIP-CMAC-128"
	case 7:
		return "GROUP-ADDRESSED"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	case 11:
		return "BIP-GMAC-128"
	case 12:
		return "BIP-GMAC-256"
	case 13:
		return "BIP-CMAC-256"
	default:
		return fmt.Sprintf("RSN(%d)", cipherType)
	}
}

func parseAKMSuite(data []byte) string {
	if len(data) < 4 {
		return "UNKNOWN"
	}

	isStandard := bytes.Equal(data[0:3], OUIWiFiAlliance)
	akmType := data[3]

	if !isStandard {
		return fmt.Sprintf("VENDOR(%02x%02x%02x:%d)", data[0], data[1], data[2], akmType)
	}

	switch akmType {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE" // WPA3-Personal
	case 9:
		return "FT-SAE"
	case 11:
		return "AKM-SUITE-B-SHA256"
	case 12:
		return "AKM-SUITE-B-SHA384"
	case 13:
		return "FT-802.1X-SHA384"
	case 14:
		return "FILS-SHA256"
	case 15:
		return "FILS-SHA384"
	case 16:
		return "FT-FILS-SHA256"
	case 17:
		return "FT-FILS-SHA384"
	case 18:
		return "OWE" // Opportunistic Wireless Encryption
	case 19:
		return "FT-PSK-SHA384"
	case 20:
		return "PSK-SHA384"
	default:
		return fmt.Sprintf("AKM(%d)", akmType)
	}
}

func parseRSNCapabilities(caps uint16) RSNCapabilities {
	return RSNCapabilities{
		PreAuth:          (caps & 0x0001) != 0,
		NoPairwise:       (caps & 0x0002) != 0,
		PTKSAReplayCount: uint8((caps >> 2) & 0x03),
		GTKSAReplayCount: uint8((caps >> 4) & 0x03),
		MFPRequired:      (caps & 0x0040) != 0,
		MFPCapable:       (caps & 0x0080) != 0,
		JointMultiBand:   (caps & 0x0100) != 0, // Bit 8
		PeerKeyEnabled:   (caps & 0x0200) != 0, // Bit 9
		OCVC:             (caps & 0x0400) != 0, // Bit 10
	}
}
