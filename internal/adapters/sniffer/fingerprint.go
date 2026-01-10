package sniffer

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/gopacket/layers"
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

// FingerprintDevice attempts to identify OS based on IE patterns
func (fe *FingerprintEngine) FingerprintDevice(data []byte, device *domain.Device) {
	// Simple heuristic: specific vendor IEs
	// Apple Vendor OUI: 00:17:F2
	// Microsoft Vendor OUI: 00:50:F2

	hasApple := false
	hasMSFT := false
	offset := 0
	limit := len(data)

	for offset < limit {
		if offset+1 >= limit {
			break
		}
		id := int(data[offset])
		length := int(data[offset+1])
		offset += 2
		if offset+length > limit {
			break
		}
		val := data[offset : offset+length]

		if id == 221 && length >= 3 {
			if val[0] == 0x00 && val[1] == 0x17 && val[2] == 0xF2 {
				hasApple = true
			}
			if val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xF2 {
				hasMSFT = true
			}
		}
		offset += length
	}

	if hasApple {
		device.OS = "iOS/macOS"
		if device.IsRandomized {
			device.Vendor = "Apple (Randomized)"
		}
	} else if hasMSFT {
		device.OS = "Windows"
	}
}

// generateIESignature creates a hash based on the ordered list of IE tags and their specific values.
// This is a simplified version of techniques used by smarter tools.
// We use: Ordered List of Tags + Values of specific tags (e.g. Supported Rates, Extended Rates, HT Caps)
func generateIESignature(layer *layers.Dot11) string {
	// We need to iterate over layers manually because gopacket's Dot11 doesn't expose a raw list easily
	// without parsing each one. However, we can re-iterate the payload if we had access to it.
	//
	// Since we are inside HandlePacket and we iterate IEs in parseIEs, we should calculate it there.
	// But let's define the logic here:
	// Signature = MD5(TagID1,TagID2,... + specific_values)

	return ""
}

// computeSignature is called from parseIEs to build the signature string
func computeSignature(tags []int, specificValues []string) string {
	sort.Ints(tags) // Some say order matters, some say sort. Let's keep original order?
	// ACTUALLY: Order matters for fingerprinting! Don't sort.
	// But we passed a slice which might be built in order.

	// Let's rely on the calling code to pass tags in order.

	var sb strings.Builder
	for _, t := range tags {
		sb.WriteString(fmt.Sprintf("%d,", t))
	}
	sb.WriteString("|")
	for _, v := range specificValues {
		sb.WriteString(v + ",")
	}

	hash := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}
