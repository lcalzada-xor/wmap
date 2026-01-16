package ie

import (
	"fmt"
)

// RSNInfo represents the parsed RSN Information Element
type RSNInfo struct {
	Version         uint16
	GroupCipher     string
	PairwiseCiphers []string
	AKMSuites       []string
	Capabilities    RSNCapabilities
}

// RSNCapabilities represents the capabilities field of RSN IE
type RSNCapabilities struct {
	PreAuth          bool
	NoPairwise       bool
	PTKSAReplayCount uint8
	GTKSAReplayCount uint8
	MFPRequired      bool
	MFPCapable       bool
	PeerKeyEnabled   bool
}

// ParseRSN parses IE 48 (RSN Information Element)
func ParseRSN(data []byte) (*RSNInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("RSN IE too short")
	}

	rsn := &RSNInfo{}
	offset := 0

	// Version (2 bytes)
	rsn.Version = uint16(data[offset]) | uint16(data[offset+1])<<8
	offset += 2

	// Group Cipher Suite (4 bytes: OUI + Type)
	if offset+4 <= len(data) {
		rsn.GroupCipher = parseCipherSuite(data[offset : offset+4])
		offset += 4
	}

	// Pairwise Cipher Suite Count + List
	if offset+2 <= len(data) {
		count := int(data[offset]) | int(data[offset+1])<<8
		offset += 2
		for i := 0; i < count && offset+4 <= len(data); i++ {
			rsn.PairwiseCiphers = append(rsn.PairwiseCiphers, parseCipherSuite(data[offset:offset+4]))
			offset += 4
		}
	}

	// AKM Suite Count + List
	if offset+2 <= len(data) {
		count := int(data[offset]) | int(data[offset+1])<<8
		offset += 2
		for i := 0; i < count && offset+4 <= len(data); i++ {
			rsn.AKMSuites = append(rsn.AKMSuites, parseAKMSuite(data[offset:offset+4]))
			offset += 4
		}
	}

	// RSN Capabilities (2 bytes)
	if offset+2 <= len(data) {
		caps := uint16(data[offset]) | uint16(data[offset+1])<<8
		rsn.Capabilities = parseRSNCapabilities(caps)
	}

	return rsn, nil
}

func parseCipherSuite(data []byte) string {
	if len(data) < 4 {
		return "UNKNOWN"
	}
	// OUI: 00-0F-AC (standard)
	cipherType := data[3]
	switch cipherType {
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP" // AES
	case 5:
		return "WEP-104"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", cipherType)
	}
}

func parseAKMSuite(data []byte) string {
	if len(data) < 4 {
		return "UNKNOWN"
	}
	akmType := data[3]
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
	case 18:
		return "OWE" // Opportunistic Wireless Encryption
	default:
		return fmt.Sprintf("UNKNOWN(%d)", akmType)
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
		PeerKeyEnabled:   (caps & 0x0200) != 0,
	}
}
