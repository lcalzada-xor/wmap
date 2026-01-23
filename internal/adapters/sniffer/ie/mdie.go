package ie

import (
	"encoding/binary"
	"fmt"
)

// MobilityDomainInfo represents the parsed Mobility Domain IE (802.11r)
type MobilityDomainInfo struct {
	MDID           uint16 // Mobility Domain ID
	OverDS         bool   // Fast BSS Transition over DS
	ResourceReq    bool   // Resource Request Protocol capability
	FTCapabilities uint8  // Raw Capability and Policy byte
}

// ParseMDIE parses the Mobility Domain IE (Tag 54)
// Structure: MDID (2 octets) | FT Capability and Policy (1 octet)
func ParseMDIE(data []byte) (*MobilityDomainInfo, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("MDIE too short: %d", len(data))
	}

	mdie := &MobilityDomainInfo{}
	mdie.MDID = binary.LittleEndian.Uint16(data[0:2])
	mdie.FTCapabilities = data[2]

	// Parse Capability Bits
	// Bit 0: Fast BSS Transition over DS
	// Bit 1: Resource Request Protocol capability
	mdie.OverDS = (mdie.FTCapabilities & 0x01) != 0
	mdie.ResourceReq = (mdie.FTCapabilities & 0x02) != 0

	return mdie, nil
}
