package driver_test

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/stretchr/testify/assert"
)

func TestParseRSN(t *testing.T) {
	// Sample RSN IE (simplified)
	data := []byte{
		0x01, 0x00, // Version
		0x00, 0x0F, 0xAC, 0x04, // Group
		0x01, 0x00, // Pairwise count
		0x00, 0x0F, 0xAC, 0x04, // Pairwise
		0x01, 0x00, // AKM count
		0x00, 0x0F, 0xAC, 0x02, // AKM (PSK)
		0x00, 0x00, // Caps
	}

	rsn, err := ie.ParseRSN(data)
	assert.NoError(t, err)

	assert.Equal(t, uint16(1), rsn.Version)
	assert.Equal(t, "CCMP", rsn.GroupCipher)
	assert.Contains(t, rsn.AKMSuites, "PSK")
}

func TestParseWPSAttributes(t *testing.T) {
	// Sample WPS IE
	data := []byte{
		0x10, 0x21, 0x00, 0x07, 'T', 'e', 's', 't', 'M', 'f', 'g',
		0x10, 0x23, 0x00, 0x09, 'T', 'e', 's', 't', 'M', 'o', 'd', 'e', 'l',
		0x10, 0x44, 0x00, 0x01, 0x02,
		0x10, 0x4A, 0x00, 0x01, 0x20,
	}

	info := ie.ParseWPSAttributes(data)

	assert.Equal(t, "Configured", info.State)
	assert.Equal(t, "2.0", info.Version)
	assert.Equal(t, "TestMfg", info.Manufacturer)
}
