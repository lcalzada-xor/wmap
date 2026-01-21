package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// --- Constants & Types ---

// DeviceCategory defines the high-level category of a matched device (e.g., IoT, Smartphone).
type DeviceCategory string

const (
	CategorySmartphone  DeviceCategory = "Smartphone"
	CategoryLaptop      DeviceCategory = "Laptop"
	CategoryIoT         DeviceCategory = "IoT"
	CategoryAccessPoint DeviceCategory = "AccessPoint"
	CategoryUnknown     DeviceCategory = "Unknown"
)

// MatchSource identifies which technique was used to match a signature.
type MatchSource string

const (
	SourceWPS       MatchSource = "WPS"
	SourceIEPattern MatchSource = "IE_Pattern"
	SourceVendorIE  MatchSource = "Vendor_IE"
	SourceOUI       MatchSource = "OUI"
)

// --- Domain Entities ---

// DeviceSignature represents a known device fingerprint pattern used for passive identification.
type DeviceSignature struct {
	ID            string         `json:"id"`
	Vendor        string         `json:"vendor"`
	DeviceType    DeviceCategory `json:"device_type"`
	Model         string         `json:"model"`
	OS            string         `json:"os"`
	OSVersionMin  string         `json:"os_version_min"`
	IEPattern     []int          `json:"ie_pattern"`      // Sequence of 802.11 Information Element tags
	IEExtensions  []int          `json:"ie_extensions"`   // Specific extension IDs
	WPSModelRegex string         `json:"wps_model_regex"` // Pattern to match against discovered WPS model names
	VendorIEOUIs  []string       `json:"vendor_ie_ouis"`  // Specific OUIs found in Vendor 802.11 IEs
	Confidence    float64        `json:"confidence"`      // Base confidence level for this signature (0.0 - 1.0)
	Sources       []MatchSource  `json:"sources"`         // Techniques supported by this signature
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// SignatureMatch represents the result of a signature comparison.
type SignatureMatch struct {
	Signature  DeviceSignature `json:"signature"`
	Confidence float64         `json:"confidence"` // Computed score based on match quality
	MatchedBy  []MatchSource   `json:"matched_by"` // Actual techniques that triggered the match
}

// --- Domain Logic ---

var (
	ErrInvalidConfidence = errors.New("confidence must be between 0.0 and 1.0")
	ErrEmptySignatureID  = errors.New("signature ID cannot be empty")
)

// Validate checks if the signature data is consistent and valid.
func (s *DeviceSignature) Validate() error {
	if s.ID == "" {
		return ErrEmptySignatureID
	}
	if s.Confidence < 0 || s.Confidence > 1 {
		return ErrInvalidConfidence
	}
	if s.WPSModelRegex != "" {
		if _, err := regexp.Compile(s.WPSModelRegex); err != nil {
			return err
		}
	}
	return nil
}

// CalculateMatch evaluates how well a Device matches this signature.
// It returns a SignatureMatch if there's any correlation, otherwise nil.
func (s *DeviceSignature) CalculateMatch(device *Device) *SignatureMatch {
	match := &SignatureMatch{
		Signature: *s,
		MatchedBy: make([]MatchSource, 0),
	}

	var score float64

	// 1. IE Pattern Matching (Heuristic weight: 0.6)
	// We check if the signature's IE pattern is a prefix of the device's IE tags.
	if len(s.IEPattern) > 0 && len(device.IETags) >= len(s.IEPattern) {
		matchCount := 0
		for i := 0; i < len(s.IEPattern); i++ {
			if device.IETags[i] == s.IEPattern[i] {
				matchCount++
			}
		}
		if matchCount == len(s.IEPattern) {
			score += 0.6
			match.MatchedBy = append(match.MatchedBy, SourceIEPattern)
		}
	}

	// 2. WPS Model Matching (Heuristic weight: 0.3)
	if s.WPSModelRegex != "" && device.Model != "" {
		re, err := regexp.Compile("(?i)" + s.WPSModelRegex)
		if err == nil && re.MatchString(device.Model) {
			score += 0.3
			match.MatchedBy = append(match.MatchedBy, SourceWPS)
		}
	}

	// 3. Vendor/OUI Matching (Heuristic weight: 0.1)
	if s.Vendor != "" && device.Vendor != "" {
		if strings.Contains(strings.ToLower(device.Vendor), strings.ToLower(s.Vendor)) {
			score += 0.1
			match.MatchedBy = append(match.MatchedBy, SourceOUI)
		}
	}

	// Optimization: Normalize and apply base signature confidence
	match.Confidence = score * s.Confidence

	if len(match.MatchedBy) == 0 {
		return nil
	}

	return match
}

// IsStrongMatch returns true if the match confidence exceeds a given threshold.
func (m *SignatureMatch) IsStrongMatch(threshold float64) bool {
	return m.Confidence >= threshold
}
