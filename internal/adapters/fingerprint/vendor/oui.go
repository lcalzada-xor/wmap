package vendor

import (
	"bufio"
	"context"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	// globalRepo is the application-level repository, initialized once at startup.
	// Deprecated: Prefer injecting VendorRepository directly for better testability.
	globalRepo     VendorRepository
	globalRepoOnce sync.Once
	globalRepoErr  error
	globalRepoMu   sync.RWMutex
)

// InitOUIDatabase initializes the global OUI database repository.
// Call this once at application startup.
// Deprecated: Use NewCompositeVendorRepository directly for better testability.
func InitOUIDatabase(dbPath string, cacheSize int) error {
	globalRepoOnce.Do(func() {
		staticRepo := NewStaticVendorRepository(CommonOUIs)

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

// LookupVendor attempts to find a vendor for a given MAC address string.
// Uses the global repository initialized by InitOUIDatabase.
// Deprecated: Use VendorRepository.LookupVendor directly for better testability.
func LookupVendor(mac string) string {
	globalRepoMu.RLock()
	repo := globalRepo
	globalRepoMu.RUnlock()

	if repo == nil {
		repo = NewStaticVendorRepository(CommonOUIs)
	}

	macAddr, err := ParseMAC(mac)
	if err != nil {
		if len(mac) >= 2 && isLocallyAdministered(mac[1]) {
			return "Randomized"
		}
		return "Unknown"
	}

	if macAddr.IsRandomized() {
		return "Randomized"
	}

	ctx := context.Background()
	vendor, err := repo.LookupVendor(ctx, macAddr)
	if err != nil {
		return "Unknown"
	}
	return vendor
}

// isLocallyAdministered checks if a hex character indicates the LAA bit is set.
func isLocallyAdministered(hexChar byte) bool {
	switch hexChar {
	case '2', '3', '6', '7', 'a', 'b', 'e', 'f', 'A', 'B', 'E', 'F':
		return true
	}
	return false
}

// FileVendorRepository loads vendor data from a plaintext file.
// Format: "XX:XX:XX Vendor Name" or "XX-XX-XX   Vendor Name"
type FileVendorRepository struct {
	vendors map[string]string
	mu      sync.RWMutex
}

// NewFileVendorRepository creates a new file-based vendor repository.
func NewFileVendorRepository() *FileVendorRepository {
	return &FileVendorRepository{
		vendors: make(map[string]string),
	}
}

// LoadFromFile loads OUI data from a text file.
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

		rawPrefix := line[0:8]
		normalized := strings.ToUpper(strings.ReplaceAll(rawPrefix, "-", ":"))

		vendor := ""
		if len(line) > 8 {
			vendor = strings.TrimSpace(line[8:])
		}

		if isValidOUI(normalized) && vendor != "" {
			newOUIs[normalized] = vendor
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	f.mu.Lock()
	for k, v := range newOUIs {
		f.vendors[k] = v
	}
	f.mu.Unlock()

	return nil
}

// LookupVendor implements VendorRepository.
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

// Close implements VendorRepository.
func (f *FileVendorRepository) Close() error {
	f.mu.Lock()
	f.vendors = make(map[string]string)
	f.mu.Unlock()
	return nil
}

// LoadOUIFile loads a text file into the global repository.
// Deprecated: Use FileVendorRepository directly for better testability.
func LoadOUIFile(path string) error {
	fileRepo := NewFileVendorRepository()
	if err := fileRepo.LoadFromFile(path); err != nil {
		return err
	}

	globalRepoMu.Lock()
	defer globalRepoMu.Unlock()

	if globalRepo == nil {
		globalRepo = fileRepo
	} else {
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
