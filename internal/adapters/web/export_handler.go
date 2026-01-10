package web

import (
	"log"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/services"
)

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
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
		alerts := s.Service.GetAlerts()
		s.exportAlerts(w, alerts, format)
		return
	}

	// Export devices - convert from GraphData
	graphData := s.Service.GetGraph()
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

	s.exportDevices(w, devices, format)
}

func (s *Server) exportDevices(w http.ResponseWriter, devices []domain.Device, format string) {
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_devices.csv")
		if err := services.ExportCSV(w, devices); err != nil {
			log.Printf("CSV export error: %v", err)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_devices.json")
		if err := services.ExportJSON(w, devices); err != nil {
			log.Printf("JSON export error: %v", err)
		}
	}
}

func (s *Server) exportAlerts(w http.ResponseWriter, alerts []domain.Alert, format string) {
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_alerts.csv")
		if err := services.ExportAlertsCSV(w, alerts); err != nil {
			log.Printf("CSV export error: %v", err)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_alerts.json")
		if err := services.ExportAlertsJSON(w, alerts); err != nil {
			log.Printf("JSON export error: %v", err)
		}
	}
}
