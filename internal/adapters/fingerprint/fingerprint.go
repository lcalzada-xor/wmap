// Package fingerprint provides device identification and fingerprinting capabilities.
// It coordinates three areas:
//   - vendor: MAC address parsing, OUI lookup, and vendor identification
//   - ie: 802.11 Information Element mapping and analysis
package fingerprint

import (
	"context"
	"net"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint/vendor"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// --- Type Aliases (vendor subpackage) ---
// These aliases maintain full backward compatibility for existing callers.

type MACAddress = vendor.MACAddress
type VendorRepository = vendor.VendorRepository
type VendorWriter = vendor.VendorWriter
type VendorStats = vendor.VendorStats
type RepositoryStats = vendor.RepositoryStats
type OUIEntry = vendor.OUIEntry
type OUICache = vendor.OUICache
type CacheStats = vendor.CacheStats
type OUIDatabase = vendor.OUIDatabase
type CompositeVendorRepository = vendor.CompositeVendorRepository
type StaticVendorRepository = vendor.StaticVendorRepository
type FileVendorRepository = vendor.FileVendorRepository

// --- Errors (vendor subpackage) ---

var (
	ErrInvalidMAC       = vendor.ErrInvalidMAC
	ErrVendorNotFound   = vendor.ErrVendorNotFound
	ErrDatabaseUnavail  = vendor.ErrDatabaseUnavailable
	ErrEmptyMAC         = vendor.ErrEmptyMAC
	ErrRepositoryClosed = vendor.ErrRepositoryClosed
)

// --- Constructor forwarding (vendor subpackage) ---

// ParseMAC parses a MAC address string. See vendor.ParseMAC for details.
func ParseMAC(s string) (MACAddress, error) { return vendor.ParseMAC(s) }

// NewMACAddress creates a MACAddress from net.HardwareAddr.
func NewMACAddress(hw net.HardwareAddr) MACAddress { return vendor.NewMACAddress(hw) }

// NewCompositeVendorRepository creates a composite chain-of-responsibility repository.
func NewCompositeVendorRepository(repos ...VendorRepository) *CompositeVendorRepository {
	return vendor.NewCompositeVendorRepository(repos...)
}

// NewStaticVendorRepository creates a static in-memory repository.
func NewStaticVendorRepository(vendors map[string]string) *StaticVendorRepository {
	return vendor.NewStaticVendorRepository(vendors)
}

// NewCachingRepository creates an LRU-caching repository wrapping an underlying one.
func NewCachingRepository(capacity int, underlying VendorRepository) *OUICache {
	return vendor.NewCachingRepository(capacity, underlying)
}

// NewOUIDatabase creates a new SQLite-backed OUI database with a fallback repository.
func NewOUIDatabase(dbPath string, cacheSize int, fallback VendorRepository) (*OUIDatabase, error) {
	return vendor.NewOUIDatabase(dbPath, cacheSize, fallback)
}

// NewFileVendorRepository creates a new file-based vendor repository.
func NewFileVendorRepository() *FileVendorRepository {
	return vendor.NewFileVendorRepository()
}

// InitOUIDatabase initializes the global OUI database. Call once at startup.
func InitOUIDatabase(dbPath string, cacheSize int) error {
	return vendor.InitOUIDatabase(dbPath, cacheSize)
}

// LookupVendor looks up a vendor name for a given MAC address string.
func LookupVendor(mac string) string { return vendor.LookupVendor(mac) }

// LoadOUIFile loads vendor data from a text file into the global repository.
func LoadOUIFile(path string) error { return vendor.LoadOUIFile(path) }

// --- Fingerprint Engine ---

// SignatureStore holds known device signatures for matching.
type SignatureStore struct {
	Signatures []domain.DeviceSignature
}

// NewSignatureStore creates a new store and pre-compiles all signatures.
func NewSignatureStore(sigs []domain.DeviceSignature) *SignatureStore {
	store := &SignatureStore{Signatures: sigs}
	for i := range store.Signatures {
		store.Signatures[i].Compile()
	}
	return store
}

// MatchSignature finds the highest-confidence match for a device.
// A match is only returned if confidence exceeds 0.5.
func (s *SignatureStore) MatchSignature(ctx context.Context, device domain.Device) *domain.SignatureMatch {
	var best *domain.SignatureMatch

	for i := range s.Signatures {
		m := s.Signatures[i].CalculateMatch(&device)
		if m == nil {
			continue
		}
		if m.Confidence > 0.5 {
			if best == nil || m.Confidence > best.Confidence {
				best = m
			}
		}
	}

	return best
}

// FingerprintEngine orchestrates device identification, combining vendor lookup,
// IE analysis, and MAC randomization detection.
type FingerprintEngine struct {
	Store *SignatureStore
}

// NewFingerprintEngine creates a new engine.
func NewFingerprintEngine(store *SignatureStore) *FingerprintEngine {
	return &FingerprintEngine{Store: store}
}

// AnalyzeRandomization detects Locally Administered Address (LAA) and marks
// the device accordingly.
func (fe *FingerprintEngine) AnalyzeRandomization(mac net.HardwareAddr, device *domain.Device) {
	m := vendor.NewMACAddress(mac)
	if m.IsRandomized() {
		device.IsRandomized = true
		device.Vendor = "Randomized"
		// Future: use IE signature to guess vendor even when MAC is randomized
	}
}
