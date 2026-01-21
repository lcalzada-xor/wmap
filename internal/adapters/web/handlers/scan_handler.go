package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// ScanHandler handles scanning, channels, and stats
type ScanHandler struct {
	Service ports.NetworkService
}

// NewScanHandler creates a new ScanHandler
func NewScanHandler(service ports.NetworkService) *ScanHandler {
	return &ScanHandler{
		Service: service,
	}
}

// HandleScan triggers an active scan
func (h *ScanHandler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Trigger Scan
	err := h.Service.TriggerScan(r.Context())
	if err != nil {
		log.Printf("Scan failed: %v", err)
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"scan_initiated"}`))
}

// HandleChannels returns available channels or updates them
func (h *ScanHandler) HandleChannels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		iface := r.URL.Query().Get("interface")
		var channels []int
		var err error

		if iface != "" {
			channels, err = h.Service.GetInterfaceChannels(ctx, iface)
		} else {
			// Fallback or Global
			channels, err = h.Service.GetChannels(ctx)
		}

		if err != nil {
			http.Error(w, "Failed to get channels: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"channels": channels,
		})
	case http.MethodPost:
		// Update channel list
		var req struct {
			Interface string `json:"interface"`
			Channels  []int  `json:"channels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var err error
		if req.Interface != "" {
			err = h.Service.SetInterfaceChannels(ctx, req.Interface, req.Channels)
		} else {
			err = h.Service.SetChannels(ctx, req.Channels)
		}

		if err != nil {
			http.Error(w, "Failed to set channels: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"channels_updated"}`))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleListInterfaces returns list of network interfaces
func (h *ScanHandler) HandleListInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use new detailed method
	details, err := h.Service.GetInterfaceDetails(r.Context())
	if err != nil {
		http.Error(w, "Failed to list interfaces: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces": details,
	})
}

// HandleGetStats returns system intelligence stats
func (h *ScanHandler) HandleGetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := h.Service.GetSystemStats(r.Context())
	if err != nil {
		http.Error(w, "Failed to get stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
