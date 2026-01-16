package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/templates"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
)

// ReportHandler handles report generation
type ReportHandler struct {
	Service          ports.NetworkService
	AuditService     ports.AuditService
	WorkspaceManager *workspace.WorkspaceManager
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
	graphData := h.Service.GetGraph()
	alerts := h.Service.GetAlerts()

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
		if node.Group == "network" {
			continue
		}

		if node.Group == "ap" || node.Group == "access_point" {
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
			Type:     node.Group,
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
