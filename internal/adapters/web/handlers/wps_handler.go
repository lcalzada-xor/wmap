package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// WPSHandler handles WPS attack operations
type WPSHandler struct {
	Service ports.NetworkService
}

// NewWPSHandler creates a new WPSHandler
func NewWPSHandler(service ports.NetworkService) *WPSHandler {
	return &WPSHandler{
		Service: service,
	}
}

// HandleStart triggers a new Pixie Dust attack
func (h *WPSHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	// Limit request body to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var config domain.WPSAttackConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Input Validation
	if config.Interface != "" && !domain.IsValidInterface(config.Interface) {
		http.Error(w, "Invalid interface name", http.StatusBadRequest)
		return
	}
	if !domain.IsValidMAC(config.TargetBSSID) {
		http.Error(w, "Invalid Target BSSID", http.StatusBadRequest)
		return
	}
	if config.Channel < 0 || config.Channel > 175 {
		http.Error(w, "Invalid Channel", http.StatusBadRequest)
		return
	}

	id, err := h.Service.StartWPSAttack(r.Context(), config)
	if err != nil {
		http.Error(w, "Failed to start attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "started"})
}

// HandleStop stops an ongoing attack
func (h *WPSHandler) HandleStop(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	force := r.URL.Query().Get("force") == "true"

	if err := h.Service.StopWPSAttack(r.Context(), id, force); err != nil {
		http.Error(w, "Failed to stop attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// HandleStatus returns the status of an attack
func (h *WPSHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	status, err := h.Service.GetWPSStatus(r.Context(), id)
	if err != nil {
		http.Error(w, "Attack not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}
