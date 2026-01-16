package domain

import "testing"

func TestIsValidMAC(t *testing.T) {
	tests := []struct {
		mac   string
		valid bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"00:11:22:33:44:55", true},
		{"invalid", false},
		{"AA:BB:CC:DD:EE", false},
		{"AA:BB:CC:DD:EE:FF:GG", false},
		{"", false},
	}

	for _, tt := range tests {
		if IsValidMAC(tt.mac) != tt.valid {
			t.Errorf("IsValidMAC(%s) = %v; want %v", tt.mac, IsValidMAC(tt.mac), tt.valid)
		}
	}
}

func TestIsValidInterface(t *testing.T) {
	tests := []struct {
		iface string
		valid bool
	}{
		{"wlan0", true},
		{"mon0", true},
		{"wlp3s0", true},
		{"eth0.100", false}, // we only allowed alphanumeric + - _
		{"very_long_interface_name_that_should_fail", false}, // > 16 chars
		{"; rm -rf /", false},
		{"", false},
	}

	for _, tt := range tests {
		if IsValidInterface(tt.iface) != tt.valid {
			t.Errorf("IsValidInterface(%s) = %v; want %v", tt.iface, IsValidInterface(tt.iface), tt.valid)
		}
	}
}
