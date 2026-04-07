package domain

import (
	"fmt"
	"net"
	"regexp"
)

// Network validation constraints based on Linux kernel standards (IFNAMSIZ)
// and IEEE 802.11 specifications.
const (
	MaxInterfaceNameLength = 16
	MaxSSIDLength          = 32
)

var (
	// reInterface validates network interface names to prevent shell injection
	// and ensure compatibility with Linux naming conventions.
	// Includes dots for VLANs/subinterfaces (e.g. eth0.100).
	reInterface = regexp.MustCompile(`^[a-zA-Z0-9\-_.]+$`)
)

// Validator defines the bridge for domain-level validation logic.
// This allows for future alternative implementations or mocked validations in tests.
type Validator interface {
	MAC(mac string) error
	Interface(name string) error
	SSID(ssid string) error
}

// DefaultValidator implements standard network validations for the WMap domain.
type DefaultValidator struct{}

// MAC validates a hardware address for both syntactic format and semantic correctness.
// It relies on the standard library net.ParseMAC for robust validation.
func (v DefaultValidator) MAC(mac string) error {
	if mac == "" {
		return fmt.Errorf("%w: cannot be empty", ErrInvalidMAC)
	}

	// Reliance on standard library for robust parsing (handles :, -, . and no-separator formats)
	if _, err := net.ParseMAC(mac); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMAC, err)
	}

	return nil
}

// Interface validates a network interface name against length and security constraints.
func (v DefaultValidator) Interface(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("%w: cannot be empty", ErrInvalidInterfaceName)
	}

	if len(name) > MaxInterfaceNameLength {
		return fmt.Errorf("%w: length %d exceeds max %d", ErrInvalidInterfaceName, len(name), MaxInterfaceNameLength)
	}

	if !reInterface.MatchString(name) {
		return fmt.Errorf("%w: contains prohibited characters", ErrInvalidInterfaceName)
	}

	return nil
}

// SSID validates an IEEE 802.11 SSID (Service Set Identifier).
func (v DefaultValidator) SSID(ssid string) error {
	if len(ssid) == 0 || len(ssid) > MaxSSIDLength {
		return fmt.Errorf("%w: length %d (must be 1-32 bytes)", ErrInvalidSSID, len(ssid))
	}
	return nil
}

// Internal singleton to handle domain validations.
var domainValidator Validator = DefaultValidator{}

// --- Public API (Preserving Backward Compatibility) ---

// IsValidMAC checks if the string is a valid MAC address.
func IsValidMAC(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

// IsValidInterface checks if the string is a safe interface name.
func IsValidInterface(iface string) bool {
	if len(iface) == 0 || len(iface) > MaxInterfaceNameLength {
		return false
	}
	return reInterface.MatchString(iface)
}

// IsValidSSID checks if the string is a valid SSID.
func IsValidSSID(ssid string) bool {
	return len(ssid) > 0 && len(ssid) <= MaxSSIDLength
}
