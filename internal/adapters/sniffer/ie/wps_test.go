package ie

import (
	"testing"
)

func TestParseWPSAttributes(t *testing.T) {
	data := []byte{
		0x10, 0x21, 0x00, 0x04, 'A', 'C', 'M', 'E', // Manufacturer
		0x10, 0x23, 0x00, 0x03, 'B', 'o', 't', // Model
	}

	info := ParseWPSAttributes(data)

	if info.Manufacturer != "ACME" {
		t.Errorf("Manufacturer = %q, want ACME", info.Manufacturer)
	}
	if info.Model != "Bot" {
		t.Errorf("Model = %q, want Bot", info.Model)
	}
}

func TestParseWPSAttributes_ModelOnly(t *testing.T) {
	data := []byte{
		0x10, 0x23, 0x00, 0x03, 'B', 'o', 't',
	}

	info := ParseWPSAttributes(data)

	if info.Model != "Bot" {
		t.Errorf("Model = %q, want Bot", info.Model)
	}
}

func TestParseWPSAttributes_Empty(t *testing.T) {
	data := []byte{}
	info := ParseWPSAttributes(data)

	if info.Model != "" || info.Manufacturer != "" {
		t.Errorf("Expected empty info, got %+v", info)
	}
}

func TestParseWPSAttributes_VersionAndState(t *testing.T) {
	data := []byte{
		0x10, 0x44, 0x00, 0x01, 0x02, // State: Configured
		0x10, 0x4A, 0x00, 0x01, 0x20, // Version: 2.0
	}

	info := ParseWPSAttributes(data)

	if info.State != "Configured" {
		t.Errorf("State = %q, want Configured", info.State)
	}
	if info.Version != "2.0" {
		t.Errorf("Version = %q, want 2.0", info.Version)
	}
}
