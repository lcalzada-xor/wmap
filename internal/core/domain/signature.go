package domain

import "time"

// DeviceSignature represents a known device fingerprint pattern
type DeviceSignature struct {
	ID            string    `json:"id"`
	Vendor        string    `json:"vendor"`
	DeviceType    string    `json:"device_type"`     // "Smartphone", "Laptop", "IoT", "AccessPoint"
	Model         string    `json:"model"`           // "iPhone 14 Pro", "Galaxy S23"
	OS            string    `json:"os"`              // "iOS", "Android", "Windows"
	OSVersionMin  string    `json:"os_version_min"`  // "16.0"
	IEPattern     []int     `json:"ie_pattern"`      // Ordered IE tags
	IEExtensions  []int     `json:"ie_extensions"`   // Extension IDs (for IE 255)
	WPSModelRegex string    `json:"wps_model_regex"` // Regex to match WPS model string
	VendorIEOUIs  []string  `json:"vendor_ie_ouis"`  // Vendor-specific IE OUIs
	Confidence    float64   `json:"confidence"`      // Base confidence (0.0-1.0)
	Sources       []string  `json:"sources"`         // ["WPS", "IE_Pattern", "Vendor_IE"]
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// SignatureMatch represents a matched signature with confidence score
type SignatureMatch struct {
	Signature  DeviceSignature `json:"signature"`
	Confidence float64         `json:"confidence"` // Computed confidence (0.0-1.0)
	MatchedBy  []string        `json:"matched_by"` // ["IE_Pattern", "WPS"]
}
