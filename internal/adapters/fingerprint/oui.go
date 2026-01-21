package fingerprint

import (
	"bufio"
	"context"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	// Global repository instance for backward compatibility
	globalRepo     VendorRepository
	globalRepoOnce sync.Once
	globalRepoErr  error
	globalRepoMu   sync.RWMutex
)

// InitOUIDatabase initializes the global OUI database repository
// This should be called once at application startup
// Deprecated: Use NewCompositeVendorRepository directly for better testability
func InitOUIDatabase(dbPath string, cacheSize int) error {
	globalRepoOnce.Do(func() {
		// Create static repository from common OUIs
		staticRepo := NewStaticVendorRepository(CommonOUIs)

		// Create database repository with static as fallback
		ouiDB, err := NewOUIDatabase(dbPath, cacheSize, staticRepo)
		if err != nil {
			log.Printf("Warning: Failed to initialize OUI database: %v. Using fallback static map.", err)
			globalRepo = staticRepo
			globalRepoErr = err
			return
		}

		ctx := context.Background()
		stats, err := ouiDB.GetStats(ctx)
		if err == nil {
			log.Printf("OUI Database initialized: %d entries, last updated %s", stats.TotalEntries, stats.LastUpdated)
		}

		globalRepo = ouiDB
	})
	return globalRepoErr
}

// LookupVendor attempts to find a vendor for a given MAC address.
// It uses the global repository initialized by InitOUIDatabase.
// Deprecated: Use VendorRepository.LookupVendor directly for better testability
func LookupVendor(mac string) string {
	globalRepoMu.RLock()
	repo := globalRepo
	globalRepoMu.RUnlock()

	// If not initialized, use static repository
	if repo == nil {
		repo = NewStaticVendorRepository(CommonOUIs)
	}

	// Parse MAC address
	macAddr, err := ParseMAC(mac)
	if err != nil {
		// Check for randomization using legacy method
		if len(mac) >= 2 && isLocallyAdministered(mac[1]) {
			return "Randomized"
		}
		return "Unknown"
	}

	// Check for randomization first
	if macAddr.IsRandomized() {
		return "Randomized"
	}

	// Lookup vendor
	ctx := context.Background()
	vendor, err := repo.LookupVendor(ctx, macAddr)
	if err != nil {
		return "Unknown"
	}

	return vendor
}

// isLocallyAdministered checks if a hex character indicates LAA bit is set
func isLocallyAdministered(hexChar byte) bool {
	// 2, 6, A, E are basic unicast LAA
	// 3, 7, B, F are multicast LAA (shouldn't be source, but possible)
	switch hexChar {
	case '2', '3', '6', '7', 'a', 'b', 'e', 'f', 'A', 'B', 'E', 'F':
		return true
	}
	return false
}

// FileVendorRepository loads vendors from a text file
type FileVendorRepository struct {
	vendors map[string]string
	mu      sync.RWMutex
}

// NewFileVendorRepository creates a new file-based vendor repository
func NewFileVendorRepository() *FileVendorRepository {
	return &FileVendorRepository{
		vendors: make(map[string]string),
	}
}

// LoadFromFile loads OUI data from a file
// Supports format: "XX:XX:XX Vendor Name" or "XX-XX-XX   Vendor Name"
func (f *FileVendorRepository) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	newOUIs := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) < 8 || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract first 8 chars as prefix
		// Expected format: "00:00:00" or "00-00-00"
		rawPrefix := line[0:8]
		normalized := strings.ToUpper(strings.ReplaceAll(rawPrefix, "-", ":"))

		vendor := ""
		if len(line) > 8 {
			vendor = strings.TrimSpace(line[8:])
		}

		// Basic validation of hex
		if isValidOUI(normalized) && vendor != "" {
			newOUIs[normalized] = vendor
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Merge into vendor map
	f.mu.Lock()
	for k, v := range newOUIs {
		f.vendors[k] = v
	}
	f.mu.Unlock()

	return nil
}

// LookupVendor implements VendorRepository interface
func (f *FileVendorRepository) LookupVendor(ctx context.Context, mac MACAddress) (string, error) {
	oui := mac.OUI()

	f.mu.RLock()
	vendor, ok := f.vendors[oui]
	f.mu.RUnlock()

	if !ok {
		return "", ErrVendorNotFound
	}

	return vendor, nil
}

// Close implements VendorRepository interface
func (f *FileVendorRepository) Close() error {
	f.mu.Lock()
	f.vendors = make(map[string]string)
	f.mu.Unlock()
	return nil
}

// LoadOUIFile loads a text file containing "OUI Vendor" lines into the global repository.
// Deprecated: Use FileVendorRepository directly for better testability
func LoadOUIFile(path string) error {
	fileRepo := NewFileVendorRepository()
	if err := fileRepo.LoadFromFile(path); err != nil {
		return err
	}

	// Add file repository to global composite
	globalRepoMu.Lock()
	defer globalRepoMu.Unlock()

	if globalRepo == nil {
		globalRepo = fileRepo
	} else {
		// Wrap in composite if not already
		if composite, ok := globalRepo.(*CompositeVendorRepository); ok {
			composite.repositories = append(composite.repositories, fileRepo)
		} else {
			globalRepo = NewCompositeVendorRepository(globalRepo, fileRepo)
		}
	}

	return nil
}

func isValidOUI(s string) bool {
	if len(s) != 8 {
		return false
	}
	if s[2] != ':' || s[5] != ':' {
		return false
	}
	return true
}
