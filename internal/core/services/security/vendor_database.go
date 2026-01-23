package security

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// VendorInfo contains default configuration information for a vendor
type VendorInfo struct {
	Vendor          string   `json:"vendor"`
	DefaultSSIDs    []string `json:"default_ssids"`
	DefaultPassword string   `json:"default_password"`
	KnownVulns      []string `json:"known_vulns"`
}

// VendorDatabase stores vendor configuration data
type VendorDatabase struct {
	vendors map[string]VendorInfo // Key: vendor name (lowercase)
	ssidMap map[string]VendorInfo // Key: SSID pattern (lowercase)
	mu      sync.RWMutex
}

// VendorDatabaseWrapper wraps the JSON structure
type VendorDatabaseWrapper struct {
	Vendors []VendorInfo `json:"vendors"`
}

// NewVendorDatabase creates an empty vendor database
func NewVendorDatabase() *VendorDatabase {
	return &VendorDatabase{
		vendors: make(map[string]VendorInfo),
		ssidMap: make(map[string]VendorInfo),
	}
}

// LoadVendorDatabase loads vendor data from a JSON file
func LoadVendorDatabase(path string) (*VendorDatabase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vendor database: %w", err)
	}

	var wrapper VendorDatabaseWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse vendor database: %w", err)
	}

	db := NewVendorDatabase()
	for _, vendor := range wrapper.Vendors {
		db.AddVendor(vendor)
	}

	return db, nil
}

// AddVendor adds a vendor to the database
func (vd *VendorDatabase) AddVendor(info VendorInfo) {
	vd.mu.Lock()
	defer vd.mu.Unlock()

	vendorKey := strings.ToLower(info.Vendor)
	vd.vendors[vendorKey] = info

	// Index by SSID patterns
	for _, ssid := range info.DefaultSSIDs {
		ssidKey := strings.ToLower(ssid)
		vd.ssidMap[ssidKey] = info
	}
}

// IsDefaultSSID checks if an SSID matches a known default pattern
func (vd *VendorDatabase) IsDefaultSSID(ssid string) (bool, VendorInfo) {
	if ssid == "" {
		return false, VendorInfo{}
	}

	vd.mu.RLock()
	defer vd.mu.RUnlock()

	ssidLower := strings.ToLower(ssid)

	// Exact match
	if info, ok := vd.ssidMap[ssidLower]; ok {
		return true, info
	}

	// Prefix match
	for pattern, info := range vd.ssidMap {
		if strings.HasPrefix(ssidLower, pattern) {
			return true, info
		}
	}

	return false, VendorInfo{}
}

// GetVendorInfo retrieves vendor information by vendor name
func (vd *VendorDatabase) GetVendorInfo(vendor string) (VendorInfo, bool) {
	vd.mu.RLock()
	defer vd.mu.RUnlock()

	vendorKey := strings.ToLower(vendor)
	info, ok := vd.vendors[vendorKey]
	return info, ok
}

// Count returns the number of vendors in the database
func (vd *VendorDatabase) Count() int {
	vd.mu.RLock()
	defer vd.mu.RUnlock()
	return len(vd.vendors)
}
