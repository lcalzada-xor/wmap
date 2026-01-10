package sniffer

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestParseWPSAttributes_Version(t *testing.T) {
	// Construct a mock byte slice mimicking WPS IEs
	// Attr Type (2), Length (2), Value
	// 0x1044 (State) -> 0x02 (Configured)
	// 0x104A (Version) -> 0x20 (2.0)

	data := []byte{
		0x10, 0x44, 0x00, 0x01, 0x02, // State: Configured
		0x10, 0x4A, 0x00, 0x01, 0x20, // Version: 2.0
	}

	device := &domain.Device{}
	ParseWPSAttributes(data, device)

	expected := "Configured (WPS 2.0)"
	if device.WPSInfo != expected {
		t.Errorf("Expected WPSInfo '%s', got '%s'", expected, device.WPSInfo)
	}

	// Test WPS 1.0
	data1 := []byte{
		0x10, 0x44, 0x00, 0x01, 0x02, // State: Configured
		0x10, 0x4A, 0x00, 0x01, 0x10, // Version: 1.0
	}
	device1 := &domain.Device{}
	ParseWPSAttributes(data1, device1)

	expected1 := "Configured (WPS 1.0)"
	if device1.WPSInfo != expected1 {
		t.Errorf("Expected WPSInfo '%s', got '%s'", expected1, device1.WPSInfo)
	}
}
