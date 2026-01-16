package mapper

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestDetectOS_Apple(t *testing.T) {
	// Apple OUI: 00:17:F2
	// Vendor IE: 221 (0xDD), Len 3+, 00 17 F2
	data := []byte{
		0xDD, 0x05, 0x00, 0x17, 0xF2, 0x01, 0x02,
	}

	dev := &domain.Device{}
	DetectOS(data, dev)

	assert.Equal(t, "iOS/macOS", dev.OS)
}

func TestDetectOS_Microsoft(t *testing.T) {
	// Microsoft OUI: 00:50:F2
	// Vendor IE: 221 (0xDD), Len 3+, 00 50 F2
	data := []byte{
		0xDD, 0x05, 0x00, 0x50, 0xF2, 0x04, 0x00,
	}

	dev := &domain.Device{}
	DetectOS(data, dev)

	assert.Equal(t, "Windows", dev.OS)
}

func TestDetectOS_Mixed(t *testing.T) {
	// Both found? First one wins in current logic (Apple checks first)
	data := []byte{
		0xDD, 0x03, 0x00, 0x50, 0xF2, // MSFT
		0xDD, 0x03, 0x00, 0x17, 0xF2, // Apple
	}

	dev := &domain.Device{}
	DetectOS(data, dev)

	assert.Equal(t, "iOS/macOS", dev.OS)
}
