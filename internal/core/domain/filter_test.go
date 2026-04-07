package domain

import (
	"strings"
	"testing"
)

func TestDeviceFilter_Matches(t *testing.T) {
	filter := &DeviceFilter{
		Vendor: "Apple",
		SSID:   "WiFi",
	}
	filter.Validate()

	device := &Device{
		Vendor: "Apple Inc.",
		SSID:   "Guest WiFi",
	}

	if !filter.Matches(device) {
		t.Errorf("Expected device to match filter")
	}

	device.Vendor = "Samsung"
	if filter.Matches(device) {
		t.Errorf("Expected device not to match filter (Vendor mismatch)")
	}
}

func TestApply(t *testing.T) {
	devices := []Device{
		{MAC: "00:11:22:33:44:55", Vendor: "Apple", RSSI: -50},
		{MAC: "00:11:22:33:44:56", Vendor: "Samsung", RSSI: -60},
		{MAC: "00:11:22:33:44:57", Vendor: "Apple", RSSI: -70},
	}

	// Use NewDeviceFilter to get sensible defaults (like MinRSSI = -120)
	filter := NewDeviceFilter().WithVendor("Apple").WithLimit(1)
	result := filter.Apply(devices)

	if len(result) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(result))
	}
	if result[0].MAC != "00:11:22:33:44:55" {
		t.Errorf("Expected first Apple device, got %s", result[0].MAC)
	}

	filter.Limit = 10
	filter.Offset = 1
	result = filter.Apply(devices)
	if len(result) != 1 {
		t.Fatalf("Expected 1 result after offset, got %d", len(result))
	}
	if result[0].MAC != "00:11:22:33:44:57" {
		t.Errorf("Expected second Apple device, got %s", result[0].MAC)
	}
}

func BenchmarkDeviceFilter_Matches_Old(b *testing.B) {
	// Reference to what the old logic did (Manual simulation)
	filter := &DeviceFilter{Vendor: "Apple", SSID: "WiFi"}
	device := &Device{Vendor: "Apple Inc.", SSID: "Guest WiFi"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulation of old logic logic: strings.ToLower(d.Vendor), strings.ToLower(f.Vendor)
		_ = strings.Contains(strings.ToLower(device.Vendor), strings.ToLower(filter.Vendor)) && 
			strings.Contains(strings.ToLower(device.SSID), strings.ToLower(filter.SSID))
	}
}

func BenchmarkDeviceFilter_Matches_New(b *testing.B) {
	filter := &DeviceFilter{Vendor: "Apple", SSID: "WiFi"}
	filter.Validate()
	device := &Device{Vendor: "Apple Inc.", SSID: "Guest WiFi"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.Matches(device)
	}
}
