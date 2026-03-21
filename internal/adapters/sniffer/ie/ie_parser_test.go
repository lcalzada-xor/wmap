package ie

import (
	"bytes"
	"testing"
)

func TestParseSSID(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected SSID
	}{
		{
			name:     "Valid SSID",
			data:     []byte{0, 4, 't', 'e', 's', 't'},
			expected: SSID{Value: "test", Hidden: false},
		},
		{
			name:     "Empty SSID",
			data:     []byte{0, 0},
			expected: SSID{Hidden: true},
		},
		{
			name:     "Zeroed SSID (Hidden)",
			data:     []byte{0, 4, 0, 0, 0, 0},
			expected: SSID{Hidden: true},
		},
		{
			name:     "Missing SSID",
			data:     []byte{3, 1, 11},
			expected: SSID{Hidden: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSSID(tt.data)
			if got != tt.expected {
				t.Errorf("ParseSSID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseCommonIEs(t *testing.T) {
	// SSID (test), Channel (11), RSN, WPS
	data := []byte{
		0, 4, 't', 'e', 's', 't', // SSID
		3, 1, 11, // Channel
		48, 4, 0x01, 0x02, 0x03, 0x04, // RSN
		221, 9, 0, 0x50, 0xF2, 4, 0x11, 0x22, 0x33, 0x44, 0x55, // WPS (OUI 00:50:f2:04)
		221, 4, 0xAA, 0xBB, 0xCC, 0xDD, // Other Vendor IE
	}

	res := ParseCommonIEs(data)

	if res.SSID.Value != "test" {
		t.Errorf("Expected SSID test, got %s", res.SSID.Value)
	}
	if res.Channel != 11 {
		t.Errorf("Expected Channel 11, got %d", res.Channel)
	}
	if !res.HasRSN {
		t.Error("Expected HasRSN true")
	}
	if !bytes.Equal(res.RSNData, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("Unexpected RSN data: %x", res.RSNData)
	}
	if !res.HasWPS {
		t.Error("Expected HasWPS true")
	}
	if !bytes.Equal(res.WPSData, []byte{0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("Unexpected WPS data: %x", res.WPSData)
	}
	if len(res.VendorIEs) != 2 {
		t.Errorf("Expected 2 VendorIEs, got %d", len(res.VendorIEs))
	}
}
