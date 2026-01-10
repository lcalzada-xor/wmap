package sniffer

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestParseWPSAttributes(t *testing.T) {
	// ... (Setup)
	data := []byte{
		0x10, 0x21, 0x00, 0x04, 'A', 'C', 'M', 'E',
		0x10, 0x23, 0x00, 0x03, 'B', 'o', 't',
	}

	expected := "ACME Bot"
	device := &domain.Device{}
	got := ParseWPSAttributes(data, device)

	if got != expected {
		t.Errorf("ParseWPSAttributes() = %q, want %q", got, expected)
	}
}

func TestParseWPSAttributes_ModelOnly(t *testing.T) {
	data := []byte{
		0x10, 0x23, 0x00, 0x03, 'B', 'o', 't',
	}

	expected := "Bot"
	device := &domain.Device{}
	got := ParseWPSAttributes(data, device)

	if got != expected {
		t.Errorf("ParseWPSAttributes() = %q, want %q", got, expected)
	}
}

func TestParseWPSAttributes_Empty(t *testing.T) {
	data := []byte{}
	expected := ""
	device := &domain.Device{}
	got := ParseWPSAttributes(data, device)

	if got != expected {
		t.Errorf("ParseWPSAttributes() = %q, want %q", got, expected)
	}
}
