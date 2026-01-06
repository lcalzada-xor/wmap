package ports

import "github.com/lcalzada-xor/wmap/internal/core/domain"

// SignatureMatcher defines the interface for matching device fingerprints to known models.
type SignatureMatcher interface {
	MatchSignature(device domain.Device) *domain.SignatureMatch
}
