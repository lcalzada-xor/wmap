package parser

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
	if len(payload) < 95 {
		return nil, fmt.Errorf("payload too short for EAPOL Key: %d bytes", len(payload))
	}

	frame := &EAPOLKeyFrame{}
	frame.DescriptorType = payload[0]

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
		frame.KeyData = payload[95:]
	}

	frame.HasMIC = (frame.KeyInformation & KeyInfoKeyMIC) != 0
	frame.HasAck = (frame.KeyInformation & KeyInfoKeyAck) != 0
	frame.IsPairwise = (frame.KeyInformation & KeyInfoKeyType) != 0
	frame.Version = uint8(frame.KeyInformation & KeyInfoKeyDescriptorVersionMask)

	return frame, nil
}

func (f *EAPOLKeyFrame) DetermineMessageNumber() int {
	if !f.IsPairwise {
		return 0
	}

	if !f.HasMIC {
		if f.HasAck {
			return 1
		}
		return 0
	}

	if f.HasAck {
		return 3
	}

	isSecure := (f.KeyInformation & KeyInfoSecure) != 0
	if !isSecure {
		if f.KeyDataLength == 0 {
			return 4
		}
		return 2
	}

	if f.KeyDataLength > 0 {
		return 2
	}

	return 4
}

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
