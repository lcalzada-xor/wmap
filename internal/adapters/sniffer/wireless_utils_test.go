package sniffer_test

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestParseRSN(t *testing.T) {
	// Sample RSN IE (simplified)
	// Version: 1 (01 00)
	// Group Cipher: CCMP (00 0F AC 04)
	// Pairwise Cipher Count: 1 (01 00)
	// Pairwise Cipher: CCMP (00 0F AC 04)
	// AKM Suite Count: 1 (01 00)
	// AKM Suite: PSK (00 0F AC 02)
	// Capabilities: 00 00
	data := []byte{
		0x01, 0x00, // Version
		0x00, 0x0F, 0xAC, 0x04, // Group
		0x01, 0x00, // Pairwise count
		0x00, 0x0F, 0xAC, 0x04, // Pairwise
		0x01, 0x00, // AKM count
		0x00, 0x0F, 0xAC, 0x02, // AKM (PSK)
		0x00, 0x00, // Caps
	}

	dev := &domain.Device{}
	sniffer.ParseIEs(append([]byte{48, byte(len(data))}, data...), dev)

	assert.Equal(t, "WPA2-PSK", dev.Security)
	assert.NotNil(t, dev.RSNInfo)
	assert.Equal(t, uint16(1), dev.RSNInfo.Version)
	assert.Equal(t, "CCMP", dev.RSNInfo.GroupCipher)
	assert.Contains(t, dev.RSNInfo.AKMSuites, "PSK")
}

func TestParseWPSAttributes(t *testing.T) {
	// Sample WPS IE (simplified)
	// Manufacturer: "TestMfg" (10 21, len 7)
	// Model: "TestModel" (10 23, len 9)
	// WPS State: Configured (10 44, len 1, val 02)
	// Version: 2.0 (10 4A, len 1, val 20)
	data := []byte{
		0x10, 0x21, 0x00, 0x07, 'T', 'e', 's', 't', 'M', 'f', 'g',
		0x10, 0x23, 0x00, 0x09, 'T', 'e', 's', 't', 'M', 'o', 'd', 'e', 'l',
		0x10, 0x44, 0x00, 0x01, 0x02,
		0x10, 0x4A, 0x00, 0x01, 0x20,
	}

	dev := &domain.Device{}
	sniffer.ParseWPSAttributes(data, dev)

	assert.Equal(t, "Configured (WPS 2.0)", dev.WPSInfo)
	assert.NotNil(t, dev.WPSDetails)
	assert.Equal(t, "2.0", dev.WPSDetails.Version)
	assert.Equal(t, "TestMfg", dev.WPSDetails.Manufacturer)
}
