package mapper

import (
	"bytes"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DetectOS attempts to identify the OS based on specfic Vendor IEs.
// It uses ie.IterateIEs for efficient parsing.
// DetectOS attempts to identify the OS based on specfic Vendor IEs.
// It uses ie.IterateIEs for efficient parsing.
func DetectOS(data []byte, device *domain.Device) {
	// Simple heuristic: specific vendor IEs
	hasApple := false
	hasMSFT := false

	ie.IterateIEs(data, func(id int, val []byte) {
		if id == IETagVendorSpecific && len(val) >= 3 {
			if bytes.HasPrefix(val, VendorApple) {
				hasApple = true
			}
			if bytes.HasPrefix(val, VendorMicrosoft) {
				hasMSFT = true
			}
		}
	})

	if hasApple {
		device.OS = "iOS/macOS"
		if device.IsRandomized {
			device.Vendor = "Apple (Randomized)"
		}
	} else if hasMSFT {
		device.OS = "Windows"
	}
}
