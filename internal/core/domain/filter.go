package domain

import "time"

// DeviceFilter defines criteria for filtering devices
type DeviceFilter struct {
	Type         string    // "ap", "station", "" (empty = any)
	MinRSSI      int       // -100 to 0
	Security     string    // "WPA2", "OPEN", "" (empty = any)
	HasWPS       *bool     // nil = any, true = only WPS, false = no WPS
	SeenAfter    time.Time // Filter devices seen after this time
	SeenBefore   time.Time // Filter devices seen before this time
	Vendor       string    // Partial match (case-insensitive)
	SSID         string    // Partial match (case-insensitive)
	IsRandomized *bool     // nil = any, true = only randomized, false = not randomized
}
