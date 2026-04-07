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
		{"00-11-22-33-44-55", true}, // Supported by net.ParseMAC
		{"0011.2233.4455", true},    // Supported by net.ParseMAC
		{"invalid", false},
		{"AA:BB:CC:DD:EE", false},
		{"AA:BB:CC:DD:EE:FF:GG", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsValidMAC(tt.mac); got != tt.valid {
			t.Errorf("IsValidMAC(%s) = %v; want %v", tt.mac, got, tt.valid)
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
		{"eth0.100", true}, // Now allowed
		{"vlan.1", true},   // Now allowed
		{"very_long_interface_name_that_should_fail", false}, // > 16 chars
		{"; rm -rf /", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsValidInterface(tt.iface); got != tt.valid {
			t.Errorf("IsValidInterface(%s) = %v; want %v", tt.iface, got, tt.valid)
		}
	}
}

func TestIsValidSSID(t *testing.T) {
	tests := []struct {
		ssid  string
		valid bool
	}{
		{"MyWiFi", true},
		{"", false},
		{"A", true},
		{"ThisIsA32CharacterSSIDLongEnough", true},
		{"ThisIsA33CharacterSSIDLongEnoughX", false},
	}

	for _, tt := range tests {
		if got := IsValidSSID(tt.ssid); got != tt.valid {
			t.Errorf("IsValidSSID(%s) = %v; want %v", tt.ssid, got, tt.valid)
		}
	}
}

func TestDefaultValidator(t *testing.T) {
	v := DefaultValidator{}

	t.Run("MAC", func(t *testing.T) {
		if err := v.MAC("AA:BB:CC:DD:EE:FF"); err != nil {
			t.Errorf("Expected valid MAC, got %v", err)
		}
		if err := v.MAC(""); err == nil {
			t.Error("Expected error for empty MAC")
		}
	})

	t.Run("Interface", func(t *testing.T) {
		if err := v.Interface("eth0.100"); err != nil {
			t.Errorf("Expected valid interface, got %v", err)
		}
	})

	t.Run("SSID", func(t *testing.T) {
		if err := v.SSID("MyWiFi"); err != nil {
			t.Errorf("Expected valid SSID, got %v", err)
		}
		if err := v.SSID(""); err == nil {
			t.Error("Expected error for empty SSID")
		}
	})
}
