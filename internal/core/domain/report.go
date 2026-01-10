package domain

import "time"

// ReportData aggregates all data needed for the security report.
type ReportData struct {
	GeneratedAt   time.Time
	GeneratedBy   string // Username
	WorkspaceName string
	Stats         ReportStats
	Devices       []Device
	Alerts        []Alert
	AuditLogs     []AuditLog
}

// ReportStats holds summary statistics.
type ReportStats struct {
	TotalDevices   int
	APCount        int
	ClientCount    int
	HighRiskAlerts int
	TotalAlerts    int
	VulnDevices    int
	TopVendors     []VendorStat

	// Security Posture
	SecurityBreakdown map[string]int

	// Channel Intelligence
	ChannelUsage map[int]int
}

type VendorStat struct {
	Name  string
	Count int
}
