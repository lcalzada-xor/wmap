package sniffer

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
)

var (
	// Global OUI database instance
	ouiDB     *fingerprint.OUIDatabase
	ouiDBOnce sync.Once
	ouiDBErr  error

	// externalOUIs holds vendors loaded from a file (legacy support)
	externalOUIs = make(map[string]string)
	ouiMutex     sync.RWMutex
)

// InitOUIDatabase initializes the OUI database
// This should be called once at application startup
func InitOUIDatabase(dbPath string, cacheSize int) error {
	ouiDBOnce.Do(func() {
		ouiDB, ouiDBErr = fingerprint.NewOUIDatabase(dbPath, cacheSize, CommonOUIs)
		if ouiDBErr != nil {
			log.Printf("Warning: Failed to initialize OUI database: %v. Using fallback static map.", ouiDBErr)
		} else {
			count, lastUpdate, err := ouiDB.GetStats()
			if err == nil {
				log.Printf("OUI Database initialized: %d entries, last updated %s", count, lastUpdate.Format("2006-01-02"))
			}
		}
	})
	return ouiDBErr
}

// LookupVendor attempts to find a vendor for a given MAC address.
// It uses the following priority:
// 1. OUI Database (if initialized)
// 2. Static Common List
// 3. Loaded External List
// 4. Randomization Check
func LookupVendor(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}
	prefix := strings.ToUpper(mac[0:8])
	prefix = strings.ReplaceAll(prefix, "-", ":") // Normalize

	// 1. Try OUI Database first (if available)
	if ouiDB != nil {
		vendor, err := ouiDB.LookupVendor(mac)
		if err == nil && vendor != "Unknown" {
			return vendor
		}
		// On error or Unknown, fall through to other methods
	}

	// 2. Check Static Common List
	if vendor, ok := CommonOUIs[prefix]; ok {
		return vendor
	}

	// 3. Check Loaded External List
	ouiMutex.RLock()
	if vendor, ok := externalOUIs[prefix]; ok {
		ouiMutex.RUnlock()
		return vendor
	}
	ouiMutex.RUnlock()

	// 4. Randomization Check
	// 2nd hex digit: 2, 6, A, E indicates locally administered
	if len(mac) >= 2 {
		c := mac[1]
		if c == '2' || c == '6' || c == 'A' || c == 'a' || c == 'E' || c == 'e' {
			return "Randomized"
		}
	}

	return "Unknown"
}

// LoadOUIFile loads a text file containing "OUI Vendor" lines.
// Supports format: "XX:XX:XX Vendor Name" or "XX-XX-XX   Vendor Name"
func LoadOUIFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
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

	// Merge into external map
	ouiMutex.Lock()
	for k, v := range newOUIs {
		externalOUIs[k] = v
	}
	ouiMutex.Unlock()

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
