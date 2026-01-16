package parser_test

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
)

func TestParseWPSAttributes_Version(t *testing.T) {
	// ...
	data := []byte{
		0x10, 0x44, 0x00, 0x01, 0x02, // State: Configured
		0x10, 0x4A, 0x00, 0x01, 0x20, // Version: 2.0
	}

	info := ie.ParseWPSAttributes(data)

	expected := "Configured"
	if info.State != expected {
		t.Errorf("Expected State '%s', got '%s'", expected, info.State)
	}
	if info.Version != "2.0" {
		t.Errorf("Expected Version 2.0, got %s", info.Version)
	}
}
