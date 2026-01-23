package ports

import (
	"context"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// CVERepository defines the interface for CVE database operations.
type CVERepository interface {
	// Query CVEs by vendor/product
	FindByVendorProduct(ctx context.Context, vendor, product string) ([]domain.CVERecord, error)

	// Search by keywords (for fuzzy matching)
	SearchByKeywords(ctx context.Context, keywords []string) ([]domain.CVERecord, error)

	// Get specific CVE by ID
	GetByID(ctx context.Context, cveID string) (*domain.CVERecord, error)

	// Sync operations
	UpsertCVE(ctx context.Context, cve domain.CVERecord) error
	GetLastSyncTime(ctx context.Context) (time.Time, error)
	UpdateSyncStatus(ctx context.Context, status domain.CVESyncStatus) error

	// Utility
	GetTotalCount(ctx context.Context) (int, error)
	Close() error
}

// CVEMatcher defines the interface for matching devices against CVE database.
type CVEMatcher interface {
	// FindMatches returns all CVE matches for a given device
	FindMatches(ctx context.Context, device domain.Device) ([]domain.CVEMatch, error)
}
