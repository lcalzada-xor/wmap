package fingerprint

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// OUIDatabase provides vendor lookup from a comprehensive OUI database
type OUIDatabase struct {
	db       *sql.DB
	cache    *OUICache
	mu       sync.RWMutex
	dbPath   string
	fallback map[string]string // Fallback to static map if DB unavailable
}

// OUIEntry represents a single OUI registry entry
type OUIEntry struct {
	Prefix      string
	Vendor      string
	VendorShort string
	Address     string
	Country     string
	LastUpdated time.Time
}

// NewOUIDatabase creates a new OUI database instance
func NewOUIDatabase(dbPath string, cacheSize int, fallback map[string]string) (*OUIDatabase, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open OUI database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping OUI database: %w", err)
	}

	oui := &OUIDatabase{
		db:       db,
		cache:    NewOUICache(cacheSize),
		dbPath:   dbPath,
		fallback: fallback,
	}

	// Create table if not exists
	if err := oui.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return oui, nil
}

// initializeSchema creates the OUI registry table if it doesn't exist
func (o *OUIDatabase) initializeSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS oui_registry (
		prefix TEXT PRIMARY KEY,
		vendor TEXT NOT NULL,
		vendor_short TEXT,
		address TEXT,
		country TEXT,
		last_updated INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_vendor ON oui_registry(vendor);
	CREATE INDEX IF NOT EXISTS idx_vendor_short ON oui_registry(vendor_short);
	`

	_, err := o.db.Exec(schema)
	return err
}

// LookupVendor looks up the vendor for a given MAC address
func (o *OUIDatabase) LookupVendor(mac string) (string, error) {
	if len(mac) < 8 {
		return "Unknown", nil
	}

	prefix := normalizeMAC(mac[:8])

	// Check cache first
	if vendor, ok := o.cache.Get(prefix); ok {
		return vendor, nil
	}

	// Query database
	var vendor string
	err := o.db.QueryRow("SELECT COALESCE(vendor_short, vendor) FROM oui_registry WHERE prefix = ?", prefix).Scan(&vendor)

	if err == sql.ErrNoRows {
		// Try fallback map
		if o.fallback != nil {
			if v, ok := o.fallback[prefix]; ok {
				o.cache.Set(prefix, v)
				return v, nil
			}
		}
		return "Unknown", nil
	}

	if err != nil {
		// On error, try fallback
		if o.fallback != nil {
			if v, ok := o.fallback[prefix]; ok {
				return v, nil
			}
		}
		return "", fmt.Errorf("database query failed: %w", err)
	}

	// Cache result
	o.cache.Set(prefix, vendor)
	return vendor, nil
}

// InsertOUI inserts or updates an OUI entry
func (o *OUIDatabase) InsertOUI(entry OUIEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	query := `
	INSERT OR REPLACE INTO oui_registry (prefix, vendor, vendor_short, address, country, last_updated)
	VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := o.db.Exec(query,
		entry.Prefix,
		entry.Vendor,
		entry.VendorShort,
		entry.Address,
		entry.Country,
		entry.LastUpdated.Unix(),
	)

	return err
}

// BulkInsertOUIs inserts multiple OUI entries in a transaction
func (o *OUIDatabase) BulkInsertOUIs(entries []OUIEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	tx, err := o.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO oui_registry (prefix, vendor, vendor_short, address, country, last_updated)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, entry := range entries {
		_, err := stmt.Exec(
			entry.Prefix,
			entry.Vendor,
			entry.VendorShort,
			entry.Address,
			entry.Country,
			entry.LastUpdated.Unix(),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetStats returns statistics about the OUI database
func (o *OUIDatabase) GetStats() (total int, lastUpdate time.Time, err error) {
	var count int
	var lastUpdateUnix int64

	err = o.db.QueryRow("SELECT COUNT(*), COALESCE(MAX(last_updated), 0) FROM oui_registry").Scan(&count, &lastUpdateUnix)
	if err != nil {
		return 0, time.Time{}, err
	}

	return count, time.Unix(lastUpdateUnix, 0), nil
}

// Close closes the database connection
func (o *OUIDatabase) Close() error {
	return o.db.Close()
}

// normalizeMAC converts a MAC prefix to standard format (XX:XX:XX)
func normalizeMAC(mac string) string {
	// Remove common separators
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, ".", ":")

	// Convert to uppercase
	mac = strings.ToUpper(mac)

	// Ensure format is XX:XX:XX
	if len(mac) >= 8 && mac[2] == ':' && mac[5] == ':' {
		return mac[:8]
	}

	// If no separators, add them
	if len(mac) >= 6 {
		return fmt.Sprintf("%s:%s:%s", mac[0:2], mac[2:4], mac[4:6])
	}

	return mac
}
