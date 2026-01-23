package cve

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

// SQLiteRepository implements ports.CVERepository using SQLite.
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new SQLite-based CVE repository.
func NewSQLiteRepository(dbPath string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	// Initialize schema
	if _, err := db.Exec(schemaSQL); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &SQLiteRepository{db: db}, nil
}

// FindByVendorProduct finds CVEs matching vendor and product.
func (r *SQLiteRepository) FindByVendorProduct(ctx context.Context, vendor, product string) ([]domain.CVERecord, error) {
	query := `
		SELECT cve_id, vendor, product, version_start, version_end, version_exact,
		       description, severity, cvss_vector, published_date, last_modified,
		       cwe_id, attack_vector, refs
		FROM cve_records
		WHERE LOWER(vendor) = LOWER(?) AND LOWER(product) = LOWER(?)
		ORDER BY severity DESC
	`

	rows, err := r.db.QueryContext(ctx, query, vendor, product)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	return r.scanCVERecords(rows)
}

// SearchByKeywords searches CVEs by keywords (fuzzy matching).
func (r *SQLiteRepository) SearchByKeywords(ctx context.Context, keywords []string) ([]domain.CVERecord, error) {
	if len(keywords) == 0 {
		return nil, nil
	}

	// Build OR conditions for description LIKE matching
	var conditions []string
	var args []interface{}

	for _, kw := range keywords {
		conditions = append(conditions, "LOWER(c.description) LIKE ?")
		args = append(args, "%"+strings.ToLower(kw)+"%")
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT c.cve_id, c.vendor, c.product, c.version_start, c.version_end, c.version_exact,
		       c.description, c.severity, c.cvss_vector, c.published_date, c.last_modified,
		       c.cwe_id, c.attack_vector, c.refs
		FROM cve_records c
		WHERE %s
		ORDER BY c.severity DESC
		LIMIT 50
	`, strings.Join(conditions, " OR "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("keyword search failed: %w", err)
	}
	defer rows.Close()

	return r.scanCVERecords(rows)
}

// GetByID retrieves a specific CVE by its ID.
func (r *SQLiteRepository) GetByID(ctx context.Context, cveID string) (*domain.CVERecord, error) {
	query := `
		SELECT cve_id, vendor, product, version_start, version_end, version_exact,
		       description, severity, cvss_vector, published_date, last_modified,
		       cwe_id, attack_vector, refs
		FROM cve_records
		WHERE cve_id = ?
	`

	row := r.db.QueryRowContext(ctx, query, cveID)
	cve, err := r.scanCVERecord(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get CVE: %w", err)
	}

	return &cve, nil
}

// UpsertCVE inserts or updates a CVE record.
func (r *SQLiteRepository) UpsertCVE(ctx context.Context, cve domain.CVERecord) error {
	// Serialize references to JSON
	refsJSON, err := json.Marshal(cve.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}

	query := `
		INSERT INTO cve_records (
			cve_id, vendor, product, version_start, version_end, version_exact,
			description, severity, cvss_vector, published_date, last_modified,
			cwe_id, attack_vector, refs
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			vendor = excluded.vendor,
			product = excluded.product,
			version_start = excluded.version_start,
			version_end = excluded.version_end,
			version_exact = excluded.version_exact,
			description = excluded.description,
			severity = excluded.severity,
			cvss_vector = excluded.cvss_vector,
			published_date = excluded.published_date,
			last_modified = excluded.last_modified,
			cwe_id = excluded.cwe_id,
			attack_vector = excluded.attack_vector,
			refs = excluded.refs,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err = r.db.ExecContext(ctx, query,
		cve.ID, cve.Vendor, cve.Product, cve.VersionStart, cve.VersionEnd, cve.VersionExact,
		cve.Description, cve.Severity, cve.CVSSVector, cve.PublishedDate.Format(time.RFC3339),
		cve.LastModified.Format(time.RFC3339), cve.CWEID, cve.AttackVector, string(refsJSON),
	)

	return err
}

// GetLastSyncTime returns the timestamp of the last CVE database sync.
func (r *SQLiteRepository) GetLastSyncTime(ctx context.Context) (time.Time, error) {
	var lastSync string
	err := r.db.QueryRowContext(ctx, "SELECT last_sync_time FROM cve_sync_status WHERE id = 1").Scan(&lastSync)
	if err != nil {
		return time.Time{}, err
	}

	return time.Parse(time.RFC3339, lastSync)
}

// UpdateSyncStatus updates the sync status.
func (r *SQLiteRepository) UpdateSyncStatus(ctx context.Context, status domain.CVESyncStatus) error {
	query := `
		UPDATE cve_sync_status
		SET last_sync_time = ?,
		    record_count = ?,
		    error_message = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`

	_, err := r.db.ExecContext(ctx, query,
		status.LastSyncTime.Format(time.RFC3339),
		status.RecordCount,
		status.ErrorMessage,
	)

	return err
}

// GetTotalCount returns the total number of CVE records.
func (r *SQLiteRepository) GetTotalCount(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM cve_records").Scan(&count)
	return count, err
}

// Close closes the database connection.
func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

// Helper: Scan multiple CVE records from rows
func (r *SQLiteRepository) scanCVERecords(rows *sql.Rows) ([]domain.CVERecord, error) {
	var cves []domain.CVERecord

	for rows.Next() {
		cve, err := r.scanCVERecordFromRows(rows)
		if err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}

	return cves, rows.Err()
}

// Helper: Scan single CVE record from row
func (r *SQLiteRepository) scanCVERecord(row *sql.Row) (domain.CVERecord, error) {
	var cve domain.CVERecord
	var publishedDate, lastModified, refsJSON string
	var versionStart, versionEnd, versionExact, cvssVector, cweID sql.NullString

	err := row.Scan(
		&cve.ID, &cve.Vendor, &cve.Product, &versionStart, &versionEnd, &versionExact,
		&cve.Description, &cve.Severity, &cvssVector, &publishedDate, &lastModified,
		&cweID, &cve.AttackVector, &refsJSON,
	)

	if err != nil {
		return cve, err
	}

	// Parse nullable fields
	cve.VersionStart = versionStart.String
	cve.VersionEnd = versionEnd.String
	cve.VersionExact = versionExact.String
	cve.CVSSVector = cvssVector.String
	cve.CWEID = cweID.String

	// Parse dates
	cve.PublishedDate, _ = time.Parse(time.RFC3339, publishedDate)
	cve.LastModified, _ = time.Parse(time.RFC3339, lastModified)

	// Parse references JSON
	if refsJSON != "" {
		json.Unmarshal([]byte(refsJSON), &cve.References)
	}

	return cve, nil
}

// Helper: Scan CVE record from rows (for multiple results)
func (r *SQLiteRepository) scanCVERecordFromRows(rows *sql.Rows) (domain.CVERecord, error) {
	var cve domain.CVERecord
	var publishedDate, lastModified, refsJSON string
	var versionStart, versionEnd, versionExact, cvssVector, cweID sql.NullString

	err := rows.Scan(
		&cve.ID, &cve.Vendor, &cve.Product, &versionStart, &versionEnd, &versionExact,
		&cve.Description, &cve.Severity, &cvssVector, &publishedDate, &lastModified,
		&cweID, &cve.AttackVector, &refsJSON,
	)

	if err != nil {
		return cve, err
	}

	// Parse nullable fields
	cve.VersionStart = versionStart.String
	cve.VersionEnd = versionEnd.String
	cve.VersionExact = versionExact.String
	cve.CVSSVector = cvssVector.String
	cve.CWEID = cweID.String

	// Parse dates
	cve.PublishedDate, _ = time.Parse(time.RFC3339, publishedDate)
	cve.LastModified, _ = time.Parse(time.RFC3339, lastModified)

	// Parse references JSON
	if refsJSON != "" {
		json.Unmarshal([]byte(refsJSON), &cve.References)
	}

	return cve, nil
}
