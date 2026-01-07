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
// 1. Randomization Check (Locally Administered Bit)
// 2. OUI Database (if initialized)
// 3. Static Common List
// 4. Loaded External List
func LookupVendor(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}

	// 1. Randomization Check (Locally Administered Bit)
	// Check if the 2nd least significant bit of the first byte is set.
	// In the string representation (hex), this corresponds to the second character.
	// First byte bits: 76543210. LAA is bit 1.
	// Hex: High Nibble (7654), Low Nibble (3210).
	// LAA bit is bit 1 of the Low Nibble.
	// Values with bit 1 set: 2 (0010), 3 (0011), 6 (0110), 7 (0111),
	// A (1010), B (1011), E (1110), F (1111).
	if len(mac) >= 2 {
		c := mac[1]
		// Check against '2','3','6','7','A','B','E','F' (case insensitive)
		// Simpler: decode the hex char/byte
		if isLocallyAdministered(c) {
			return "Randomized"
		}
	}

	prefix := strings.ToUpper(mac[0:8])
	prefix = strings.ReplaceAll(prefix, "-", ":") // Normalize

	// 2. Try OUI Database first (if available)
	if ouiDB != nil {
		vendor, err := ouiDB.LookupVendor(mac)
		if err == nil && vendor != "Unknown" {
			return vendor
		}
		// On error or Unknown, fall through to other methods
	}

	// 3. Check Static Common List
	if vendor, ok := CommonOUIs[prefix]; ok {
		return vendor
	}

	// 4. Check Loaded External List
	ouiMutex.RLock()
	if vendor, ok := externalOUIs[prefix]; ok {
		ouiMutex.RUnlock()
		return vendor
	}
	ouiMutex.RUnlock()

	return "Unknown"
}

func isLocallyAdministered(hexChar byte) bool {
	// 2, 6, A, E are basic unicast LAA
	// 3, 7, B, F are multicast LAA (shouldn't be source, but possible)
	switch hexChar {
	case '2', '3', '6', '7', 'a', 'b', 'e', 'f', 'A', 'B', 'E', 'F':
		return true
	}
	return false
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
