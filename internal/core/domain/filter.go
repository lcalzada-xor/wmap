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
	Type         string    `json:"type"`          // "ap", "station", "" (empty = any)
	MinRSSI      int       `json:"min_rssi"`      // -120 to 0
	Security     string    `json:"security"`      // "WPA2", "OPEN", "" (empty = any)
	HasWPS       *bool     `json:"has_wps"`       // nil = any, true = only WPS, false = no WPS
	SeenAfter    time.Time `json:"seen_after"`    // Filter devices seen after this time
	SeenBefore   time.Time `json:"seen_before"`   // Filter devices seen before this time
	Vendor       string    `json:"vendor"`        // Partial match (case-insensitive)
	SSID         string    `json:"ssid"`          // Partial match (case-insensitive)
	IsRandomized *bool     `json:"is_randomized"` // nil = any

	// Pagination
	Limit  int `json:"limit"`
	Offset int `json:"offset"`

	// Internal pre-calculated fields for performance
	vendorLower string
	ssidLower   string
	isCompiled  bool
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

func (f *DeviceFilter) WithVendor(v string) *DeviceFilter {
	f.Vendor = v
	return f
}

func (f *DeviceFilter) WithLimit(limit int) *DeviceFilter {
	f.Limit = limit
	return f
}

func (f *DeviceFilter) WithOffset(offset int) *DeviceFilter {
	f.Offset = offset
	return f
}

// Validate ensures the filter criteria are architecturally and logically valid.
// It also triggers internal compilation of search terms for performance.
func (f *DeviceFilter) Validate() error {
	if f.MinRSSI < -120 || f.MinRSSI > 0 {
		return ErrInvalidRSSI
	}
	if !f.SeenAfter.IsZero() && !f.SeenBefore.IsZero() && f.SeenAfter.After(f.SeenBefore) {
		return ErrInvalidTimeRange
	}

	f.compile()
	return nil
}

func (f *DeviceFilter) compile() {
	if f.Vendor != "" {
		f.vendorLower = strings.ToLower(f.Vendor)
	}
	if f.SSID != "" {
		f.ssidLower = strings.ToLower(f.SSID)
	}
	f.isCompiled = true
}

// Apply filters a slice of devices in-memory, including pagination.
func (f *DeviceFilter) Apply(devices []Device) []Device {
	// Ensure filter is compiled
	if !f.isCompiled {
		f.compile()
	}

	var filtered []Device
	for _, d := range devices {
		if f.Matches(&d) {
			filtered = append(filtered, d)
		}
	}

	// Apply Offset
	if f.Offset >= len(filtered) {
		return []Device{}
	}
	filtered = filtered[f.Offset:]

	// Apply Limit
	if f.Limit > 0 && f.Limit < len(filtered) {
		filtered = filtered[:f.Limit]
	}

	return filtered
}

// Matches implements the Specification Pattern.
// It allows filtering of devices in-memory, ensuring consistency between DB queries and local logic.
func (f *DeviceFilter) Matches(d *Device) bool {
	if d == nil {
		return false
	}

	// Ensure compilation (usually called via Validate, but safe here too)
	if !f.isCompiled {
		f.compile()
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
		// Detect WPS presence consistently with the storage layer: 
		// Field is not empty OR detail pointer exists.
		hasWPS := d.WPSInfo != "" || d.WPSDetails != nil
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

	// 6. Vendor Match (Case-insensitive partial, optimized)
	if f.vendorLower != "" && !strings.Contains(strings.ToLower(d.Vendor), f.vendorLower) {
		return false
	}

	// 7. SSID Match (Case-insensitive partial, optimized)
	if f.ssidLower != "" && !strings.Contains(strings.ToLower(d.SSID), f.ssidLower) {
		return false
	}

	// 8. Randomized MAC Match (from Identity embedded struct)
	if f.IsRandomized != nil && d.IsRandomized != *f.IsRandomized {
		return false
	}

	return true
}
