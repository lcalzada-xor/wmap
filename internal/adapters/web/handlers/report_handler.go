package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/reporting"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/templates"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	reportingService "github.com/lcalzada-xor/wmap/internal/core/services/reporting"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
)

// ReportHandler handles report generation
type ReportHandler struct {
	Service          ports.NetworkService
	AuditService     ports.AuditService
	WorkspaceManager *workspace.WorkspaceManager
	// New Phase 2 fields
	ExecutiveGenerator *reportingService.ExecutiveReportGenerator
	PDFExporter        *reporting.PDFExporter
}

// NewReportHandler creates a new ReportHandler
func NewReportHandler(service ports.NetworkService, auditService ports.AuditService, workspaceManager *workspace.WorkspaceManager) *ReportHandler {
	return &ReportHandler{
		Service:          service,
		AuditService:     auditService,
		WorkspaceManager: workspaceManager,
	}
}

// HandleGenerateReport aggregates data and renders the HTML report
func (h *ReportHandler) HandleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Get User Info from Context
	user, ok := r.Context().Value(middleware.UserContextKey).(*domain.User)
	username := "Unknown"
	if ok && user != nil {
		username = user.Username
	}

	// 2. Fetch Data from Services
	graphData, err := h.Service.GetGraph(r.Context())
	if err != nil {
		http.Error(w, "Failed to get graph data: "+err.Error(), http.StatusInternalServerError)
		return
	}
	alerts, err := h.Service.GetAlerts(r.Context())
	if err != nil {
		alerts = []domain.Alert{} // Graceful degradation
	}

	// Default limit for report logs
	auditLogs, err := h.AuditService.GetLogs(r.Context(), 50)
	if err != nil {
		auditLogs = []domain.AuditLog{} // Fail graceful
	}

	// 3. Aggregate Stats & Devices
	stats := domain.ReportStats{
		TotalDevices:      len(graphData.Nodes),
		TotalAlerts:       len(alerts),
		SecurityBreakdown: make(map[string]int),
		ChannelUsage:      make(map[int]int),
	}

	devices := make([]domain.Device, 0)
	vendorMap := make(map[string]int)

	for _, node := range graphData.Nodes {
		if node.Group == domain.GroupNetwork {
			continue
		}

		if node.Group == domain.GroupAP {
			stats.APCount++
		} else {
			stats.ClientCount++
		}

		if node.Vendor != "" {
			vendorMap[node.Vendor]++
		} else {
			vendorMap["Unknown"]++
		}

		// Security Stats
		sec := node.Security
		if sec == "" {
			sec = "OPEN"
		}
		stats.SecurityBreakdown[sec]++

		// Channel Stats
		if node.Channel > 0 {
			stats.ChannelUsage[node.Channel]++
		}

		// Convert GraphNode -> Device (Simplified)
		devices = append(devices, domain.Device{
			MAC:      node.MAC,
			Type:     domain.DeviceType(node.Group),
			Vendor:   node.Vendor,
			SSID:     node.Label, // Graph uses Label for SSID usually, or ID
			RSSI:     node.RSSI,
			Security: node.Security,
		})
	}

	// Calculate Top Vendors
	var vendors []domain.VendorStat
	for k, v := range vendorMap {
		vendors = append(vendors, domain.VendorStat{Name: k, Count: v})
	}
	// Sort by count desc
	sort.Slice(vendors, func(i, j int) bool {
		return vendors[i].Count > vendors[j].Count
	})
	// Top 10
	if len(vendors) > 10 {
		vendors = vendors[:10]
	}
	stats.TopVendors = vendors

	// Count High Risk Alerts
	for _, a := range alerts {
		if a.Severity == domain.SeverityHigh || a.Severity == domain.SeverityCritical {
			stats.HighRiskAlerts++
		}
	}

	// 4. Construct Report Data
	data := domain.ReportData{
		GeneratedAt:   time.Now(),
		GeneratedBy:   username,
		WorkspaceName: h.WorkspaceManager.GetCurrentWorkspace(),
		Stats:         stats,
		Devices:       devices, // Might want to limit this if huge
		Alerts:        alerts,
		AuditLogs:     auditLogs,
	}

	// 5. Parse Template
	tmpl, err := template.New("report").Parse(templates.SecurityReportHTML)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 6. Serve Response
	filename := fmt.Sprintf("wmap_report_%s.html", time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	if err := tmpl.Execute(w, data); err != nil {
		// If we already wrote header, this might be messy, but acceptable for now
		return
	}
}

// ============================================================================
// Phase 2: Executive Summary Report Generation
// ============================================================================

// HandleGenerateExecutiveSummary generates an executive summary report
func (h *ReportHandler) HandleGenerateExecutiveSummary(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StartDate string `json:"start_date"` // YYYY-MM-DD format
		EndDate   string `json:"end_date"`   // YYYY-MM-DD format
		OrgName   string `json:"org_name"`
		Format    string `json:"format"` // pdf, json
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse dates
	var dateRange domain.DateRange
	if req.StartDate != "" {
		start, err := time.Parse("2006-01-02", req.StartDate)
		if err != nil {
			http.Error(w, "Invalid start_date format (use YYYY-MM-DD)", http.StatusBadRequest)
			return
		}
		dateRange.Start = start
	}

	if req.EndDate != "" {
		end, err := time.Parse("2006-01-02", req.EndDate)
		if err != nil {
			http.Error(w, "Invalid end_date format (use YYYY-MM-DD)", http.StatusBadRequest)
			return
		}
		dateRange.End = end
	}

	// If no dates specified, use last 30 days
	if dateRange.Start.IsZero() && dateRange.End.IsZero() {
		dateRange.End = time.Now()
		dateRange.Start = dateRange.End.AddDate(0, 0, -30)
	}

	// Default format to PDF
	if req.Format == "" {
		req.Format = "pdf"
	}

	// Check if executive generator is available
	if h.ExecutiveGenerator == nil {
		http.Error(w, "Executive report generator not initialized", http.StatusInternalServerError)
		return
	}

	// Generate report
	report, err := h.ExecutiveGenerator.Generate(r.Context(), dateRange, req.OrgName)
	if err != nil {
		http.Error(w, "Failed to generate report: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Export based on format
	switch req.Format {
	case "pdf":
		if h.PDFExporter == nil {
			http.Error(w, "PDF exporter not initialized", http.StatusInternalServerError)
			return
		}

		data, err := h.PDFExporter.ExportExecutiveSummary(report)
		if err != nil {
			http.Error(w, "Failed to export PDF: "+err.Error(), http.StatusInternalServerError)
			return
		}

		filename := "wmap-executive-summary.pdf"
		if req.OrgName != "" {
			filename = fmt.Sprintf("wmap-executive-summary-%s.pdf", req.OrgName)
		}

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Write(data)

	case "json":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)

	default:
		http.Error(w, "Unsupported format: "+req.Format, http.StatusBadRequest)
	}
}
