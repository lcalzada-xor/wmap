package domain

import (
	"errors"
	"strings"
	"time"
)

// Security type constants
const (
	SecurityWPA3 = "WPA3"
	SecurityWPA2 = "WPA2"
	SecurityWEP  = "WEP"
	SecurityOpen = "OPEN"
)

// Domain Errors for filtering
var (
	ErrInvalidRSSI      = errors.New("RSSI must be between -120 and 0")
	ErrInvalidTimeRange = errors.New("SeenAfter cannot be later than SeenBefore")
)

// DeviceFilter defines criteria for filtering and querying devices.
// It follows the Specification Pattern by providing a Matches method to encapsulate filtering logic.
type DeviceFilter struct {
	Type               string    `json:"type"`                // "ap", "station", "" (empty = any)
	MinRSSI            int       `json:"min_rssi"`            // -120 to 0
	Security           string    `json:"security"`            // "WPA2", "OPEN", "" (empty = any)
	HasWPS             *bool     `json:"has_wps"`             // nil = any, true = only WPS, false = no WPS
	SeenAfter          time.Time `json:"seen_after"`          // Filter devices seen after this time
	SeenBefore         time.Time `json:"seen_before"`         // Filter devices seen before this time
	Vendor             string    `json:"vendor"`              // Partial match (case-insensitive)
	SSID               string    `json:"ssid"`                // Partial match (case-insensitive)
	IsRandomized       *bool     `json:"is_randomized"`       // nil = any
	MinSeverity        Severity  `json:"min_severity"`        // Minimal vulnerability severity (1-10)
	HasVulnerabilities *bool     `json:"has_vulnerabilities"` // nil = any
}

// NewDeviceFilter initializes a filter with sensible defaults.
func NewDeviceFilter() *DeviceFilter {
	return &DeviceFilter{
		MinRSSI: -120, // Default to lowest detectable signal
	}
}

// --- Builder Pattern Methods ---

func (f *DeviceFilter) WithType(t string) *DeviceFilter {
	f.Type = t
	return f
}

func (f *DeviceFilter) WithMinRSSI(rssi int) *DeviceFilter {
	f.MinRSSI = rssi
	return f
}

func (f *DeviceFilter) WithSecurity(s string) *DeviceFilter {
	f.Security = s
	return f
}

func (f *DeviceFilter) WithSSID(ssid string) *DeviceFilter {
	f.SSID = ssid
	return f
}

// Validate ensures the filter criteria are architecturally and logically valid.
func (f *DeviceFilter) Validate() error {
	if f.MinRSSI < -120 || f.MinRSSI > 0 {
		return ErrInvalidRSSI
	}
	if !f.SeenAfter.IsZero() && !f.SeenBefore.IsZero() && f.SeenAfter.After(f.SeenBefore) {
		return ErrInvalidTimeRange
	}
	return nil
}

// Matches implements the Specification Pattern.
// It allows filtering of devices in-memory, ensuring consistency between DB queries and local logic.
func (f *DeviceFilter) Matches(d *Device) bool {
	if d == nil {
		return false
	}

	// 1. Type Match (d.Type is DeviceType)
	if f.Type != "" && !strings.EqualFold(string(d.Type), f.Type) {
		return false
	}

	// 2. RSSI Match (d.RSSI is in Radio embedded struct)
	if d.RSSI < f.MinRSSI {
		return false
	}

	// 3. Security Match (d.Security)
	if f.Security != "" && !strings.EqualFold(d.Security, f.Security) {
		return false
	}

	// 4. WPS Match
	if f.HasWPS != nil {
		// Logic inferred from Device struct (WPSInfo and WPSDetails pointer)
		hasWPS := strings.Contains(strings.ToUpper(d.WPSInfo), "WPS") || d.WPSDetails != nil
		if *f.HasWPS != hasWPS {
			return false
		}
	}

	// 5. Time Match (d.LastSeen is in Radio embedded struct)
	if !f.SeenAfter.IsZero() && d.LastSeen.Before(f.SeenAfter) {
		return false
	}
	if !f.SeenBefore.IsZero() && d.LastSeen.After(f.SeenBefore) {
		return false
	}

	// 6. Vendor Match (Case-insensitive partial, from Identity embedded struct)
	if f.Vendor != "" && !strings.Contains(strings.ToLower(d.Vendor), strings.ToLower(f.Vendor)) {
		return false
	}

	// 7. SSID Match (Case-insensitive partial)
	if f.SSID != "" && !strings.Contains(strings.ToLower(d.SSID), strings.ToLower(f.SSID)) {
		return false
	}

	// 8. Randomized MAC Match (from Identity embedded struct)
	if f.IsRandomized != nil && d.IsRandomized != *f.IsRandomized {
		return false
	}

	// 9. Vulnerability Filtering
	if f.HasVulnerabilities != nil {
		hasVulns := len(d.Vulnerabilities) > 0
		if *f.HasVulnerabilities != hasVulns {
			return false
		}
	}

	if f.MinSeverity > 0 {
		maxSev := Severity(0)
		for _, v := range d.Vulnerabilities {
			if v.Severity > maxSev {
				maxSev = v.Severity
			}
		}
		if maxSev < f.MinSeverity {
			return false
		}
	}

	return true
}
