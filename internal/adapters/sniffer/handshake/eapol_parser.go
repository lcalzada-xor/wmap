package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// KeyInformation masks (IEEE 802.11i)
const (
	KeyInfoKeyDescriptorVersionMask = 0x0007 // Bits 0-2
	KeyInfoKeyType                  = 1 << 3 // Bit 3 (1=Pairwise, 0=Group)
	KeyInfoKeyIndexMask             = 0x0030 // Bits 4-5
	KeyInfoInstall                  = 1 << 6 // Bit 6
	KeyInfoKeyAck                   = 1 << 7 // Bit 7
	KeyInfoKeyMIC                   = 1 << 8 // Bit 8
	KeyInfoSecure                   = 1 << 9 // Bit 9
	KeyInfoError                    = 1 << 10
	KeyInfoRequest                  = 1 << 11
	KeyInfoEncryptedKeyData         = 1 << 12
)

// EAPOLKeyFrame represents the parsed fields of an EAPOL Key frame.
type EAPOLKeyFrame struct {
	DescriptorType uint8
	KeyInformation uint16
	KeyLength      uint16
	ReplayCounter  uint64
	Nonce          []byte // 32 bytes
	KeyIV          []byte // 16 bytes
	KeyRSC         uint64 // 8 bytes (represented as uint64 for convenience, though strictly byte array)
	KeyID          uint64 // 8 bytes reserved
	MIC            []byte // 16 bytes (usually)
	KeyDataLength  uint16
	KeyData        []byte

	// Helper flags for easy logic
	HasMIC     bool
	HasAck     bool
	IsPairwise bool
	Version    uint8
}

// ParseEAPOLKey parses a gopacket.Packet and returns a structured EAPOLKeyFrame.
// Returns nil if the packet is not a valid EAPOL Key frame.
func ParseEAPOLKey(packet gopacket.Packet) (*EAPOLKeyFrame, error) {
	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return nil, errors.New("not an EAPOL packet")
	}

	eapol, ok := eapolLayer.(*layers.EAPOL)
	if !ok {
		return nil, errors.New("failed to cast to EAPOL layer")
	}

	if eapol.Type != layers.EAPOLTypeKey {
		return nil, fmt.Errorf("not an EAPOL Key frame (Type: %d)", eapol.Type)
	}

	payload := eapol.LayerPayload()
	// Minimum length check: 1 (DescType) + 2 (KeyInfo) + 2 (KeyLen) + 8 (Replay) + 32 (Nonce) + 16 (IV) + 8 (RSC) + 8 (ID) + 16 (MIC) + 2 (DataLen) = 95 bytes
	if len(payload) < 95 {
		return nil, fmt.Errorf("payload too short for EAPOL Key: %d bytes", len(payload))
	}

	frame := &EAPOLKeyFrame{}
	frame.DescriptorType = payload[0]

	// Key Information (Big Endian)
	frame.KeyInformation = binary.BigEndian.Uint16(payload[1:3])
	frame.KeyLength = binary.BigEndian.Uint16(payload[3:5])
	frame.ReplayCounter = binary.BigEndian.Uint64(payload[5:13])
	frame.Nonce = payload[13:45]
	frame.KeyIV = payload[45:61]
	frame.KeyRSC = binary.BigEndian.Uint64(payload[61:69])
	frame.KeyID = binary.BigEndian.Uint64(payload[69:77])
	frame.MIC = payload[77:93]
	frame.KeyDataLength = binary.BigEndian.Uint16(payload[93:95])

	if len(payload) >= 95+int(frame.KeyDataLength) {
		frame.KeyData = payload[95 : 95+int(frame.KeyDataLength)]
	} else {
		// Truncated data, but maybe still usable?
		frame.KeyData = payload[95:]
	}

	// Parse Flags
	frame.HasMIC = (frame.KeyInformation & KeyInfoKeyMIC) != 0
	frame.HasAck = (frame.KeyInformation & KeyInfoKeyAck) != 0
	frame.IsPairwise = (frame.KeyInformation & KeyInfoKeyType) != 0
	frame.Version = uint8(frame.KeyInformation & KeyInfoKeyDescriptorVersionMask)

	return frame, nil
}

// DetermineMessageNumber infers if this is M1, M2, M3, or M4 of the 4-way handshake.
// Returns 0 if it cannot be determined or is not part of the standard 4-way.
func (f *EAPOLKeyFrame) DetermineMessageNumber() int {
	if !f.IsPairwise {
		// Group Key Handshake (not 4-way) - usually M1 (Group Key) and M2 (Ack)
		// We are primarily interested in 4-way for cracking
		return 0
	}

	if !f.HasMIC {
		// Message 1: No MIC, Ack=1
		if f.HasAck {
			return 1
		}
		return 0
	}

	// Has MIC
	if f.HasAck {
		// Message 3: MIC=1, Ack=1, Install=1 (usually)
		// Secure bit might be set
		return 3
	}

	// Has MIC, No Ack
	// Could be M2 or M4
	// M2: KeyDataLength > 0 (contains RSN IE)
	// M4: KeyDataLength = 0 (usually), or very small (padding?)
	// Actually M4 Secure bit should be 1. M2 Secure bit 0.
	isSecure := (f.KeyInformation & KeyInfoSecure) != 0

	if !isSecure {
		// Secure=0. Standard M2.
		// Robustness: What if it's M4 with missing Secure bit?
		// Check KeyDataLength. M2 must have data (RSN IE). M4 usually doesn't.
		if f.KeyDataLength == 0 {
			// Weird case. Secure=0 but no data.
			// Likely M4 from non-compliant AP? Or M2 with no RSN IE?
			// Let's assume M4 if data is empty, as M2 MUST have RSN IE.
			return 4
		}
		return 2 // M2
	}

	// Secure=1, No Ack, MIC=1 -> M4
	// Robustness: What if it's M2 with Secure=1 (invalid)?
	// If DataLen > 0, probably M2 or M3? But M3 has Ack=1.
	// So purely M2 vs M4.
	// Secure=1, No Ack, MIC=1 -> M4
	// Robustness: What if it's M2 with Secure=1 (invalid)?
	// If DataLen > 0, probably M2 or M3? But M3 has Ack=1.
	// So purely M2 vs M4.
	if f.KeyDataLength > 0 {
		// Has data, but Secure=1.
		// Could be Group Key Handshake (M1)? No, we checked IsPairwise already.
		// Maybe M2 with Secure bit wrongly set?
		// Let's prefer Data presence = M2.
		return 2
	}

	return 4
}

// IsMICZero checks if the MIC is all zeros (invalid).
func (f *EAPOLKeyFrame) IsMICZero() bool {
	if !f.HasMIC || len(f.MIC) == 0 {
		return true
	}
	for _, b := range f.MIC {
		if b != 0 {
			return false
		}
	}
	return true
}
