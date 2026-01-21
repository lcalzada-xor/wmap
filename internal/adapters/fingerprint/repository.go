package fingerprint

import (
	"context"
)

// VendorRepository defines the interface for looking up device vendors by MAC address
type VendorRepository interface {
	// LookupVendor returns the vendor name for a given MAC address
	LookupVendor(ctx context.Context, mac MACAddress) (string, error)

	// Close releases any resources held by the repository
	Close() error
}

// VendorWriter defines the interface for writing vendor data
type VendorWriter interface {
	// InsertOUI inserts or updates a single OUI entry
	InsertOUI(ctx context.Context, entry OUIEntry) error

	// BulkInsertOUIs inserts multiple OUI entries in a transaction
	BulkInsertOUIs(ctx context.Context, entries []OUIEntry) error
}

// VendorStats provides statistics about the vendor repository
type VendorStats interface {
	// GetStats returns statistics about the repository
	GetStats(ctx context.Context) (RepositoryStats, error)
}

// RepositoryStats contains statistics about a vendor repository
type RepositoryStats struct {
	TotalEntries int
	CacheHits    int64
	CacheMisses  int64
	LastUpdated  string
}

// CompositeVendorRepository implements a chain-of-responsibility pattern
// for vendor lookups, trying multiple repositories in order
type CompositeVendorRepository struct {
	repositories []VendorRepository
}

// NewCompositeVendorRepository creates a new composite repository
// that tries each repository in order until one succeeds
func NewCompositeVendorRepository(repos ...VendorRepository) *CompositeVendorRepository {
	return &CompositeVendorRepository{
		repositories: repos,
	}
}

// LookupVendor tries each repository in order until one returns a result
func (c *CompositeVendorRepository) LookupVendor(ctx context.Context, mac MACAddress) (string, error) {
	if !mac.IsValid() {
		return "", ErrInvalidMAC
	}

	var lastErr error
	for _, repo := range c.repositories {
		vendor, err := repo.LookupVendor(ctx, mac)
		if err == nil && vendor != "" && vendor != "Unknown" {
			return vendor, nil
		}
		if err != nil && err != ErrVendorNotFound {
			lastErr = err
		}
	}

	if lastErr != nil {
		return "Unknown", lastErr
	}
	return "Unknown", ErrVendorNotFound
}

// Close closes all repositories
func (c *CompositeVendorRepository) Close() error {
	var firstErr error
	for _, repo := range c.repositories {
		if err := repo.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// StaticVendorRepository provides vendor lookups from an in-memory map
type StaticVendorRepository struct {
	vendors map[string]string
}

// NewStaticVendorRepository creates a new static repository
func NewStaticVendorRepository(vendors map[string]string) *StaticVendorRepository {
	return &StaticVendorRepository{
		vendors: vendors,
	}
}

// LookupVendor looks up a vendor in the static map
func (s *StaticVendorRepository) LookupVendor(ctx context.Context, mac MACAddress) (string, error) {
	oui := mac.OUI()
	if vendor, ok := s.vendors[oui]; ok {
		return vendor, nil
	}
	return "", ErrVendorNotFound
}

// Close is a no-op for static repository
func (s *StaticVendorRepository) Close() error {
	return nil
}
