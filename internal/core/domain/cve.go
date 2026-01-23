package domain

import "time"

// CVERecord represents a Common Vulnerabilities and Exposures entry
// from the National Vulnerability Database (NVD) or similar sources.
type CVERecord struct {
	ID      string `json:"cve_id"`  // e.g., "CVE-2020-3111"
	Vendor  string `json:"vendor"`  // e.g., "cisco"
	Product string `json:"product"` // e.g., "wap321"

	// Version Matching
	VersionStart string `json:"version_start,omitempty"` // e.g., "1.0.0"
	VersionEnd   string `json:"version_end,omitempty"`   // e.g., "1.4.5"
	VersionExact string `json:"version_exact,omitempty"` // e.g., "1.2.3"

	// Metadata
	Description   string    `json:"description"`
	Severity      float64   `json:"severity"`              // CVSS Score 0-10
	CVSSVector    string    `json:"cvss_vector,omitempty"` // e.g., "CVSS:3.1/AV:N/AC:L/..."
	PublishedDate time.Time `json:"published_date"`
	LastModified  time.Time `json:"last_modified,omitempty"`

	// Classification
	CWEID        string `json:"cwe_id,omitempty"` // e.g., "CWE-79"
	AttackVector string `json:"attack_vector"`    // NETWORK, ADJACENT, LOCAL

	// References
	References []string `json:"references,omitempty"` // URLs to advisories, patches, etc.
}

// CVEMatch represents a match between a device and a CVE record.
type CVEMatch struct {
	CVE        CVERecord `json:"cve"`
	Confidence float64   `json:"confidence"` // 0.0-1.0
	MatchType  string    `json:"match_type"` // "exact", "wps", "keyword"
	Evidence   []string  `json:"evidence"`   // What triggered the match
}

// CVESyncStatus tracks the last synchronization with external CVE databases.
type CVESyncStatus struct {
	LastSyncTime time.Time `json:"last_sync_time"`
	RecordCount  int       `json:"record_count"`
	ErrorMessage string    `json:"error_message,omitempty"`
}
