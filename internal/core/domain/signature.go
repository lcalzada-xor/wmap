package domain

import (
	"errors"
	"regexp"
	"strings"
	"sync"
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

	// Unexported fields for performance optimization
	mu         sync.RWMutex
	rx         *regexp.Regexp
	normVendor string
	compiled   bool
}

// SignatureMatch represents the result of a signature comparison.
type SignatureMatch struct {
	Signature  *DeviceSignature `json:"signature"`
	Confidence float64          `json:"confidence"` // Computed score based on match quality
	MatchedBy  []MatchSource    `json:"matched_by"` // Actual techniques that triggered the match
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
		// Just validate syntax
		if _, err := regexp.Compile(s.WPSModelRegex); err != nil {
			return err
		}
	}
	return nil
}

// Compile pre-processes the signature for faster matching.
// It should be called after loading signatures and before starting the match engine.
func (s *DeviceSignature) Compile() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.WPSModelRegex != "" {
		s.rx, _ = regexp.Compile("(?i)" + s.WPSModelRegex)
	}
	if s.Vendor != "" {
		s.normVendor = strings.ToLower(s.Vendor)
	}
	s.compiled = true
}

// CalculateMatch evaluates how well a Device matches this signature.
// It returns a SignatureMatch if there's any correlation, otherwise nil.
func (s *DeviceSignature) CalculateMatch(device *Device) *SignatureMatch {
	// 1. Fast Path: Check if we have any data to match at all
	if len(s.IEPattern) == 0 && s.WPSModelRegex == "" && s.Vendor == "" {
		return nil
	}

	// Ensure we are compiled (optional fallback if not explicitly called)
	s.mu.RLock()
	if !s.compiled {
		s.mu.RUnlock()
		s.Compile()
		s.mu.RLock()
	}
	rx := s.rx
	normVendor := s.normVendor
	s.mu.RUnlock()

	var score float64
	var matchedBy []MatchSource

	// 2. IE Pattern Matching (Heuristic weight: 0.6)
	if len(s.IEPattern) > 0 && len(device.IETags) >= len(s.IEPattern) {
		matchCount := 0
		for i := 0; i < len(s.IEPattern); i++ {
			if device.IETags[i] == s.IEPattern[i] {
				matchCount++
			}
		}
		if matchCount == len(s.IEPattern) {
			score += 0.6
			matchedBy = append(matchedBy, SourceIEPattern)
		}
	}

	// 3. WPS Model Matching (Heuristic weight: 0.3)
	if rx != nil && device.Model != "" {
		if rx.MatchString(device.Model) {
			score += 0.3
			matchedBy = append(matchedBy, SourceWPS)
		}
	}

	// 4. Vendor/OUI Matching (Heuristic weight: 0.1)
	if normVendor != "" && device.Vendor != "" {
		if strings.Contains(strings.ToLower(device.Vendor), normVendor) {
			score += 0.1
			matchedBy = append(matchedBy, SourceOUI)
		}
	}

	if len(matchedBy) == 0 {
		return nil
	}

	// Optimization: Normalize and apply base signature confidence
	return &SignatureMatch{
		Signature:  s,
		Confidence: score * s.Confidence,
		MatchedBy:  matchedBy,
	}
}

// IsStrongMatch returns true if the match confidence exceeds a given threshold.
func (m *SignatureMatch) IsStrongMatch(threshold float64) bool {
	return m.Confidence >= threshold
}
