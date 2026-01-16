package fingerprint

import (
	"net"
	"strings"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// SignatureStore holds known device signatures.
type SignatureStore struct {
	Signatures []domain.DeviceSignature
}

// NewSignatureStore creates a new store.
func NewSignatureStore(sigs []domain.DeviceSignature) *SignatureStore {
	return &SignatureStore{Signatures: sigs}
}

// FingerprintEngine handles device identification logic.
type FingerprintEngine struct {
	Store *SignatureStore
}

// NewFingerprintEngine creates a new engine.
func NewFingerprintEngine(store *SignatureStore) *FingerprintEngine {
	return &FingerprintEngine{Store: store}
}

// MatchSignature attempts to find the best match for a device.
func (s *SignatureStore) MatchSignature(device domain.Device) *domain.SignatureMatch {
	var bestMatch *domain.SignatureMatch
	maxConfidence := 0.0

	for _, sig := range s.Signatures {
		confidence := 0.0
		var matchedBy []string

		// 1. IE Pattern Match (Sequence of Tags)
		if len(sig.IEPattern) > 0 && len(device.IETags) >= len(sig.IEPattern) {
			// Subsequence matching or exact?
			// Fingerprinting often uses the exact sequence of the first N tags.
			matchCount := 0
			for i := 0; i < len(sig.IEPattern); i++ {
				if i < len(device.IETags) && device.IETags[i] == sig.IEPattern[i] {
					matchCount++
				}
			}
			if matchCount == len(sig.IEPattern) {
				confidence += 0.6
				matchedBy = append(matchedBy, "IE_Pattern")
			}
		}

		// 2. WPS Model Match
		if sig.WPSModelRegex != "" && device.Model != "" {
			if strings.Contains(strings.ToLower(device.Model), strings.ToLower(sig.WPSModelRegex)) {
				confidence += 0.3
				matchedBy = append(matchedBy, "WPS")
			}
		}

		// 3. Vendor OUI Match (from MAC)
		if sig.Vendor != "" && strings.Contains(strings.ToLower(device.Vendor), strings.ToLower(sig.Vendor)) {
			confidence += 0.1
		}

		if confidence > 0.5 && confidence > maxConfidence {
			maxConfidence = confidence
			bestMatch = &domain.SignatureMatch{
				Signature:  sig,
				Confidence: confidence,
				MatchedBy:  matchedBy,
			}
		}
	}

	return bestMatch
}

// AnalyzeRandomization checks for Locally Administered Address
func (fe *FingerprintEngine) AnalyzeRandomization(mac net.HardwareAddr, device *domain.Device) {
	if len(mac) > 0 && (mac[0]&0x02) != 0 {
		device.IsRandomized = true
		device.Vendor = "Randomized"
		// Future: Use Signature to guess vendor even if randomized
	}
}
