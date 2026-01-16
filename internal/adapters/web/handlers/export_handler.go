package handlers

import (
	"log"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/export"
)

// ExportHandler handles data export
type ExportHandler struct {
	Service ports.NetworkService
}

// NewExportHandler creates a new ExportHandler
func NewExportHandler(service ports.NetworkService) *ExportHandler {
	return &ExportHandler{
		Service: service,
	}
}

// HandleExport exports data
func (h *ExportHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	dataType := r.URL.Query().Get("type")
	if dataType == "" {
		dataType = "devices"
	}

	// Handle alerts export
	if dataType == "alerts" {
		alerts := h.Service.GetAlerts()
		h.exportAlerts(w, alerts, format)
		return
	}

	// Export devices - convert from GraphData
	graphData := h.Service.GetGraph()
	devices := make([]domain.Device, 0)

	for _, node := range graphData.Nodes {
		if node.Group == "network" {
			continue
		}
		device := domain.Device{
			MAC:      node.MAC,
			Type:     node.Group,
			Vendor:   node.Vendor,
			RSSI:     node.RSSI,
			Security: node.Security,
			Standard: node.Standard,
			Model:    node.Model,
			LastSeen: node.LastSeen,
		}
		devices = append(devices, device)
	}

	h.exportDevices(w, devices, format)
}

func (h *ExportHandler) exportDevices(w http.ResponseWriter, devices []domain.Device, format string) {
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_devices.csv")
		if err := export.ExportCSV(w, devices); err != nil {
			log.Printf("CSV export error: %v", err)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_devices.json")
		if err := export.ExportJSON(w, devices); err != nil {
			log.Printf("JSON export error: %v", err)
		}
	}
}

func (h *ExportHandler) exportAlerts(w http.ResponseWriter, alerts []domain.Alert, format string) {
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_alerts.csv")
		if err := export.ExportAlertsCSV(w, alerts); err != nil {
			log.Printf("CSV export error: %v", err)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_alerts.json")
		if err := export.ExportAlertsJSON(w, alerts); err != nil {
			log.Printf("JSON export error: %v", err)
		}
	}
}
