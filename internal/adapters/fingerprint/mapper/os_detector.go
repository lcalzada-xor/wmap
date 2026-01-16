package mapper

import (
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DetectOS attempts to identify the OS based on specfic Vendor IEs.
// It uses ie.IterateIEs for efficient parsing.
func DetectOS(data []byte, device *domain.Device) {
	// Simple heuristic: specific vendor IEs
	// Apple Vendor OUI: 00:17:F2
	// Microsoft Vendor OUI: 00:50:F2

	hasApple := false
	hasMSFT := false

	ie.IterateIEs(data, func(id int, val []byte) {
		if id == 221 && len(val) >= 3 {
			if val[0] == 0x00 && val[1] == 0x17 && val[2] == 0xF2 {
				hasApple = true
			}
			if val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xF2 {
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
