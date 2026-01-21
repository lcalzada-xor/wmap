package fingerprint

import (
	"fmt"
	"net"
	"strings"
)

// MACAddress is a value object representing a validated MAC address
type MACAddress struct {
	address net.HardwareAddr
}

// ParseMAC parses a MAC address string into a MACAddress value object.
// Supports formats: "XX:XX:XX:XX:XX:XX", "XX-XX-XX-XX-XX-XX", "XXXXXXXXXXXX"
func ParseMAC(s string) (MACAddress, error) {
	if s == "" {
		return MACAddress{}, ErrEmptyMAC
	}

	// Normalize separators to colons
	normalized := strings.ReplaceAll(s, "-", ":")
	normalized = strings.ReplaceAll(normalized, ".", ":")

	// If no separators, add them (assumes 12 hex chars)
	if !strings.Contains(normalized, ":") && len(normalized) == 12 {
		// Insert colons every 2 characters
		var parts []string
		for i := 0; i < len(normalized); i += 2 {
			if i+2 <= len(normalized) {
				parts = append(parts, normalized[i:i+2])
			}
		}
		normalized = strings.Join(parts, ":")
	}

	// Parse using net.ParseMAC
	hw, err := net.ParseMAC(normalized)
	if err != nil {
		return MACAddress{}, &ValidationError{
			Field: "mac",
			Value: s,
			Err:   ErrInvalidMAC,
		}
	}

	return MACAddress{address: hw}, nil
}

// MustParseMAC parses a MAC address and panics on error.
// Only use in tests or with known-valid input.
func MustParseMAC(s string) MACAddress {
	mac, err := ParseMAC(s)
	if err != nil {
		panic(fmt.Sprintf("invalid MAC address %q: %v", s, err))
	}
	return mac
}

// NewMACAddress creates a MACAddress from net.HardwareAddr
func NewMACAddress(hw net.HardwareAddr) MACAddress {
	return MACAddress{address: hw}
}

// OUI returns the Organizationally Unique Identifier (first 3 bytes) as "XX:XX:XX"
func (m MACAddress) OUI() string {
	if len(m.address) < 3 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X",
		m.address[0],
		m.address[1],
		m.address[2],
	)
}

// IsRandomized checks if the MAC address has the Locally Administered Address (LAA) bit set.
// This is the second least significant bit of the first octet.
func (m MACAddress) IsRandomized() bool {
	if len(m.address) == 0 {
		return false
	}
	// Check bit 1 of the first byte (0x02)
	return (m.address[0] & 0x02) != 0
}

// IsMulticast checks if the MAC address is a multicast address.
// This is the least significant bit of the first octet.
func (m MACAddress) IsMulticast() bool {
	if len(m.address) == 0 {
		return false
	}
	// Check bit 0 of the first byte (0x01)
	return (m.address[0] & 0x01) != 0
}

// IsUnicast returns true if the address is a unicast address
func (m MACAddress) IsUnicast() bool {
	return !m.IsMulticast()
}

// IsUniversal returns true if the address is universally administered (not locally administered)
func (m MACAddress) IsUniversal() bool {
	return !m.IsRandomized()
}

// String returns the MAC address in standard format "XX:XX:XX:XX:XX:XX"
func (m MACAddress) String() string {
	return strings.ToUpper(m.address.String())
}

// HardwareAddr returns the underlying net.HardwareAddr
func (m MACAddress) HardwareAddr() net.HardwareAddr {
	return m.address
}

// Equal compares two MAC addresses for equality
func (m MACAddress) Equal(other MACAddress) bool {
	return m.address.String() == other.address.String()
}

// IsValid returns true if the MAC address is valid (non-empty)
func (m MACAddress) IsValid() bool {
	return len(m.address) > 0
}
