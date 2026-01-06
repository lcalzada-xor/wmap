package sniffer

import (
	"os"
	"testing"
)

func TestLookupVendor(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected string
	}{
		{"Apple Device", "00:03:93:11:22:33", "Apple"},
		{"Intel Device", "00:02:B3:AA:BB:CC", "Intel"},
		{"Randomized MAC (x2)", "02:00:00:00:00:00", "Randomized"},
		{"Randomized MAC (x6)", "06:11:22:33:44:55", "Randomized"},
		{"Randomized MAC (xA)", "0A:AA:BB:CC:DD:EE", "Randomized"},
		{"Randomized MAC (xE)", "0E:FF:EE:DD:CC:BB", "Randomized"},
		{"Unknown Device", "11:22:33:44:55:66", "Unknown"},
		{"Short MAC", "00:11", "Unknown"},
		{"Dash Separator", "00-03-93-11-22-33", "Apple"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LookupVendor(tt.mac)
			if got != tt.expected {
				t.Errorf("LookupVendor(%s) = %v, want %v", tt.mac, got, tt.expected)
			}
		})
	}
}

func TestLoadOUIFile(t *testing.T) {
	// Create a temp file
	content := `
# Comment
11:22:33 TestVendor1
AA-BB-CC   TestVendor2
	`
	tmpfile, err := os.CreateTemp("", "oui_test_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load it
	if err := LoadOUIFile(tmpfile.Name()); err != nil {
		t.Fatalf("LoadOUIFile failed: %v", err)
	}

	// Verify
	if got := LookupVendor("11:22:33:00:00:00"); got != "TestVendor1" {
		t.Errorf("Got %s, want TestVendor1", got)
	}
	if got := LookupVendor("AA:BB:CC:DD:EE:FF"); got != "TestVendor2" {
		t.Errorf("Got %s, want TestVendor2", got)
	}
}
