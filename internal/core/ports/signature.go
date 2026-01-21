package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// SignatureMatcher identifies device models and manufacturers based on captured attributes.
type SignatureMatcher interface {
	// MatchSignature compares device data against a library of known fingerprints.
	MatchSignature(ctx context.Context, device domain.Device) *domain.SignatureMatch
}
