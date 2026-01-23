package domain

import (
	"time"
)

// ReportTitle represents a standard name for different types of reports.
type ReportTitle string

const (
	TitleSecurityAudit ReportTitle = "Security Audit Report"
	TitleNetworkStatus ReportTitle = "Network Status Report"
	TitleIncidentLog   ReportTitle = "Incident Investigation Report"
)

// ReportData acts as a domain aggregate that represents a snapshot of the system state
// at a specific point in time for audit and compliance purposes.
type ReportData struct {
	ID            string      `json:"id"`
	Title         ReportTitle `json:"title"`
	GeneratedAt   time.Time   `json:"generated_at"`
	GeneratedBy   string      `json:"generated_by"` // Username or User ID
	WorkspaceName string      `json:"workspace_name"`
	Stats         ReportStats `json:"stats"`
	Devices       []Device    `json:"devices,omitempty"`
	Alerts        []Alert     `json:"alerts,omitempty"`
	AuditLogs     []AuditLog  `json:"audit_logs,omitempty"`
}

// ReportStats provides a high-level summary of the report data.
type ReportStats struct {
	TotalDevices   int `json:"total_devices"`
	APCount        int `json:"ap_count"`
	ClientCount    int `json:"client_count"`
	HighRiskAlerts int `json:"high_risk_alerts"`
	TotalAlerts    int `json:"total_alerts"`
	VulnDevices    int `json:"vulnerable_devices"`

	// Complex aggregations
	TopVendors        []VendorStat   `json:"top_vendors"`
	SecurityBreakdown map[string]int `json:"security_breakdown"`
	ChannelUsage      map[int]int    `json:"channel_usage"`
}

// VendorStat represents a count of devices per vendor.
type VendorStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// NewReportData is a factory that creates a ReportData and automatically computes its statistics.
func NewReportData(user string, workspace string, devices []Device, alerts []Alert, logs []AuditLog) *ReportData {
	r := &ReportData{
		Title:         TitleSecurityAudit,
		GeneratedAt:   time.Now().UTC(),
		GeneratedBy:   user,
		WorkspaceName: workspace,
		Devices:       devices,
		Alerts:        alerts,
		AuditLogs:     logs,
	}

	r.RecomputeStats()
	return r
}

// RecomputeStats executes the internal business logic to derive summaries from raw data.
func (r *ReportData) RecomputeStats() {
	stats := ReportStats{
		TotalDevices:      len(r.Devices),
		TotalAlerts:       len(r.Alerts),
		SecurityBreakdown: make(map[string]int),
		ChannelUsage:      make(map[int]int),
	}

	vendorMap := make(map[string]int)

	for i := range r.Devices {
		d := &r.Devices[i]

		// 1. Device Category Distribution
		if d.IsAP() {
			stats.APCount++
		} else if d.IsStation() {
			stats.ClientCount++
		}

		// 2. Vendor Aggregation
		vName := d.Vendor // Inlined from Identity
		if vName == "" {
			vName = "Unknown"
		}
		vendorMap[vName]++

		// 3. Security Breakdown
		sec := d.Security
		if sec == "" {
			sec = "OPEN"
		}
		stats.SecurityBreakdown[sec]++

		// 4. Radio Channel usage
		if d.Channel > 0 {
			stats.ChannelUsage[d.Channel]++
		}

		// 5. Vulnerability check
		if len(d.Vulnerabilities) > 0 {
			stats.VulnDevices++
		}
	}

	// 6. Alert risk analysis
	for _, a := range r.Alerts {
		if a.Severity == SeverityCritical || a.Severity == SeverityHigh {
			stats.HighRiskAlerts++
		}
	}

	// 7. Process Top Vendors (Top 10 sorted by count)
	for name, count := range vendorMap {
		stats.TopVendors = append(stats.TopVendors, VendorStat{Name: name, Count: count})
	}

	// Internal Sort (Bubble sort style to avoid external dependencies for simple logic)
	for i := 0; i < len(stats.TopVendors); i++ {
		for j := i + 1; j < len(stats.TopVendors); j++ {
			if stats.TopVendors[i].Count < stats.TopVendors[j].Count {
				stats.TopVendors[i], stats.TopVendors[j] = stats.TopVendors[j], stats.TopVendors[i]
			}
		}
	}

	if len(stats.TopVendors) > 10 {
		stats.TopVendors = stats.TopVendors[:10]
	}

	r.Stats = stats
}

// Validate checks if the report has the minimum required data to be considered valid.
func (r *ReportData) Validate() bool {
	return r.WorkspaceName != "" && !r.GeneratedAt.IsZero()
}

// ============================================================================
// New Reporting System (Phase 2)
// ============================================================================

// ReportType represents the type of security report
type ReportType string

const (
	ReportTypeExecutive  ReportType = "executive"
	ReportTypeTechnical  ReportType = "technical"
	ReportTypeCompliance ReportType = "compliance"
	ReportTypeTrend      ReportType = "trend"
)

// ReportFormat represents the export format for reports
type ReportFormat string

const (
	FormatPDF      ReportFormat = "pdf"
	FormatHTML     ReportFormat = "html"
	FormatJSON     ReportFormat = "json"
	FormatCSV      ReportFormat = "csv"
	FormatMarkdown ReportFormat = "markdown"
)

// ReportMetadata contains metadata about a generated report
type ReportMetadata struct {
	ID               string       `json:"id"`
	Type             ReportType   `json:"type"`
	Format           ReportFormat `json:"format"`
	Title            string       `json:"title"`
	GeneratedAt      time.Time    `json:"generated_at"`
	GeneratedBy      string       `json:"generated_by"`
	ScanPeriod       DateRange    `json:"scan_period"`
	WorkspaceName    string       `json:"workspace_name"`
	OrganizationName string       `json:"organization_name,omitempty"`
}

// DateRange represents a time period
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ExecutiveSummary is a high-level security report for management
type ExecutiveSummary struct {
	Metadata        ReportMetadata     `json:"metadata"`
	RiskScore       float64            `json:"risk_score"` // 0-10
	RiskLevel       string             `json:"risk_level"` // Low, Medium, High, Critical
	TotalDevices    int                `json:"total_devices"`
	VulnStats       VulnerabilityStats `json:"vulnerability_stats"`
	TopRisks        []RiskItem         `json:"top_risks"`
	Recommendations []Recommendation   `json:"recommendations"`
}

// VulnerabilityStats provides statistical breakdown of vulnerabilities
type VulnerabilityStats struct {
	Total       int            `json:"total"`
	Critical    int            `json:"critical"`
	High        int            `json:"high"`
	Medium      int            `json:"medium"`
	Low         int            `json:"low"`
	BySeverity  map[string]int `json:"by_severity"`
	ByCategory  map[string]int `json:"by_category"`
	ByStatus    map[string]int `json:"by_status"`
	Confirmed   int            `json:"confirmed"`
	Unconfirmed int            `json:"unconfirmed"`
}

// RiskItem represents a prioritized security risk
type RiskItem struct {
	Rank            int     `json:"rank"`
	VulnName        string  `json:"vulnerability_name"`
	Severity        int     `json:"severity"`
	AffectedDevices int     `json:"affected_devices"`
	Impact          string  `json:"impact"`
	Likelihood      string  `json:"likelihood"`
	RiskScore       float64 `json:"risk_score"`
}

// Recommendation provides actionable security guidance
type Recommendation struct {
	Priority        string   `json:"priority"` // critical, high, medium, low
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Actions         []string `json:"actions"`
	EstimatedEffort string   `json:"estimated_effort"`
	ImpactReduction float64  `json:"impact_reduction"` // 0-100%
}
