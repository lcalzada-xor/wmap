package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// ConfigHandler handles configuration settings
type ConfigHandler struct {
	Service ports.NetworkService
}

// NewConfigHandler creates a new ConfigHandler
func NewConfigHandler(service ports.NetworkService) *ConfigHandler {
	return &ConfigHandler{
		Service: service,
	}
}

// HandleGetConfig returns current configuration
func (h *ConfigHandler) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"persistenceEnabled": h.Service.IsPersistenceEnabled(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// HandleTogglePersistence toggles data persistence
func (h *ConfigHandler) HandleTogglePersistence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabledStr := r.URL.Query().Get("enabled")
	enabled := enabledStr == "true"
	h.Service.SetPersistenceEnabled(enabled)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"persistence_updated","enabled":%v}`, enabled)
}
