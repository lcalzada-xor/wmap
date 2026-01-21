package fingerprint

import (
	"context"
	"net"

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

// MatchSignature attempts to find the best match for a device using domain-defined heuristics.
func (s *SignatureStore) MatchSignature(ctx context.Context, device domain.Device) *domain.SignatureMatch {
	var bestMatch *domain.SignatureMatch

	for _, sig := range s.Signatures {
		currentMatch := sig.CalculateMatch(&device)
		if currentMatch == nil {
			continue
		}

		// Higher confidence match found.
		// Note: We use 0.5 as a minimal quality threshold as defined in previous logic.
		if currentMatch.Confidence > 0.5 {
			if bestMatch == nil || currentMatch.Confidence > bestMatch.Confidence {
				bestMatch = currentMatch
			}
		}
	}

	return bestMatch
}

// AnalyzeRandomization checks for Locally Administered Address
func (fe *FingerprintEngine) AnalyzeRandomization(mac net.HardwareAddr, device *domain.Device) {
	m := MACAddress{address: mac}
	if m.IsRandomized() {
		device.IsRandomized = true
		device.Vendor = "Randomized"
		// Future: Use Signature to guess vendor even if randomized
	}
}
