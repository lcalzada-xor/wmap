package domain

import (
	"regexp"
)

// Validation Helpers

var (
	macRegex       = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	interfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
)

// IsValidMAC checks if the string is a valid MAC address
func IsValidMAC(mac string) bool {
	return macRegex.MatchString(mac)
}

// IsValidInterface checks if the string is a safe interface name (alphanumeric + - _)
func IsValidInterface(iface string) bool {
	// Length check (Linux interfaces are usually short, IFNAMSIZ is 16)
	if len(iface) == 0 || len(iface) > 16 {
		return false
	}
	return interfaceRegex.MatchString(iface)
}
