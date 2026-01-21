package fingerprint

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// OUIDatabase provides vendor lookup from a comprehensive OUI database
// It implements VendorRepository, VendorWriter, and VendorStats interfaces
type OUIDatabase struct {
	db       *sql.DB
	cache    *OUICache
	mu       sync.RWMutex
	dbPath   string
	fallback VendorRepository
	closed   bool

	// Prepared statements for better performance
	lookupStmt *sql.Stmt
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
func NewOUIDatabase(dbPath string, cacheSize int, fallback VendorRepository) (*OUIDatabase, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, &DatabaseError{Op: "open", Err: err}
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, &DatabaseError{Op: "ping", Err: err}
	}

	oui := &OUIDatabase{
		db:       db,
		cache:    NewOUICache(cacheSize),
		dbPath:   dbPath,
		fallback: fallback,
	}

	// Create table if not exists
	if err := oui.initializeSchema(); err != nil {
		db.Close()
		return nil, &DatabaseError{Op: "initialize_schema", Err: err}
	}

	// Prepare lookup statement
	stmt, err := db.Prepare("SELECT COALESCE(vendor_short, vendor) FROM oui_registry WHERE prefix = ?")
	if err != nil {
		db.Close()
		return nil, &DatabaseError{Op: "prepare_statement", Err: err}
	}
	oui.lookupStmt = stmt

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
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	return nil
}

// LookupVendor implements VendorRepository interface
func (o *OUIDatabase) LookupVendor(ctx context.Context, mac MACAddress) (string, error) {
	o.mu.RLock()
	if o.closed {
		o.mu.RUnlock()
		return "", ErrRepositoryClosed
	}
	o.mu.RUnlock()

	if !mac.IsValid() {
		return "", ErrInvalidMAC
	}

	prefix := mac.OUI()

	// Check cache first
	if vendor, ok := o.cache.Get(prefix); ok {
		return vendor, nil
	}

	// Query database with context
	var vendor string
	err := o.lookupStmt.QueryRowContext(ctx, prefix).Scan(&vendor)

	if err == sql.ErrNoRows {
		// Try fallback repository
		if o.fallback != nil {
			v, err := o.fallback.LookupVendor(ctx, mac)
			if err == nil && v != "" && v != "Unknown" {
				o.cache.Set(prefix, v)
				return v, nil
			}
		}
		return "Unknown", ErrVendorNotFound
	}

	if err != nil {
		// On error, try fallback
		if o.fallback != nil {
			v, err := o.fallback.LookupVendor(ctx, mac)
			if err == nil {
				return v, nil
			}
		}
		return "", &DatabaseError{Op: "lookup", Err: err}
	}

	// Cache result
	o.cache.Set(prefix, vendor)
	return vendor, nil
}

// InsertOUI implements VendorWriter interface
func (o *OUIDatabase) InsertOUI(ctx context.Context, entry OUIEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return ErrRepositoryClosed
	}

	query := `
	INSERT OR REPLACE INTO oui_registry (prefix, vendor, vendor_short, address, country, last_updated)
	VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := o.db.ExecContext(ctx, query,
		entry.Prefix,
		entry.Vendor,
		entry.VendorShort,
		entry.Address,
		entry.Country,
		entry.LastUpdated.Unix(),
	)

	if err != nil {
		return &DatabaseError{Op: "insert", Err: err}
	}

	return nil
}

// BulkInsertOUIs implements VendorWriter interface
func (o *OUIDatabase) BulkInsertOUIs(ctx context.Context, entries []OUIEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return ErrRepositoryClosed
	}

	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return &DatabaseError{Op: "begin_transaction", Err: err}
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO oui_registry (prefix, vendor, vendor_short, address, country, last_updated)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return &DatabaseError{Op: "prepare_bulk_insert", Err: err}
	}
	defer stmt.Close()

	for _, entry := range entries {
		_, err := stmt.ExecContext(ctx,
			entry.Prefix,
			entry.Vendor,
			entry.VendorShort,
			entry.Address,
			entry.Country,
			entry.LastUpdated.Unix(),
		)
		if err != nil {
			return &DatabaseError{Op: "bulk_insert_entry", Err: err}
		}
	}

	if err := tx.Commit(); err != nil {
		return &DatabaseError{Op: "commit_transaction", Err: err}
	}

	return nil
}

// GetStats implements VendorStats interface
func (o *OUIDatabase) GetStats(ctx context.Context) (RepositoryStats, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.closed {
		return RepositoryStats{}, ErrRepositoryClosed
	}

	var count int
	var lastUpdateUnix int64

	err := o.db.QueryRowContext(ctx,
		"SELECT COUNT(*), COALESCE(MAX(last_updated), 0) FROM oui_registry",
	).Scan(&count, &lastUpdateUnix)

	if err != nil {
		return RepositoryStats{}, &DatabaseError{Op: "get_stats", Err: err}
	}

	lastUpdate := time.Unix(lastUpdateUnix, 0).Format("2006-01-02")
	cacheStats := o.cache.Stats()

	return RepositoryStats{
		TotalEntries: count,
		CacheHits:    cacheStats.Hits,
		CacheMisses:  cacheStats.Misses,
		LastUpdated:  lastUpdate,
	}, nil
}

// Close implements VendorRepository interface
func (o *OUIDatabase) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil
	}

	o.closed = true

	// Close prepared statement
	if o.lookupStmt != nil {
		o.lookupStmt.Close()
	}

	// Close cache
	if o.cache != nil {
		o.cache.Close()
	}

	// Close database
	if o.db != nil {
		return o.db.Close()
	}

	return nil
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
