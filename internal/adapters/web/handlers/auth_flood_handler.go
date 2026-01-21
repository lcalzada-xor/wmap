package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// AuthFloodHandler handles authentication flood attacks
type AuthFloodHandler struct {
	Service ports.NetworkService
}

// NewAuthFloodHandler creates a new AuthFloodHandler
func NewAuthFloodHandler(service ports.NetworkService) *AuthFloodHandler {
	return &AuthFloodHandler{
		Service: service,
	}
}

// HandleStart triggers a new auth flood attack
func (h *AuthFloodHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	// Limit request body to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var config domain.AuthFloodAttackConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	id, err := h.Service.StartAuthFloodAttack(r.Context(), config)
	if err != nil {
		http.Error(w, "Failed to start attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "started"})
}

// HandleStop stops an ongoing attack
func (h *AuthFloodHandler) HandleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attackID := r.URL.Query().Get("id")
	if attackID == "" {
		http.Error(w, "attack id is required", http.StatusBadRequest)
		return
	}

	force := r.URL.Query().Get("force") == "true"

	if err := h.Service.StopAuthFloodAttack(r.Context(), attackID, force); err != nil {
		http.Error(w, "Failed to stop attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// HandleStatus returns the status of an attack
func (h *AuthFloodHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	status, err := h.Service.GetAuthFloodStatus(r.Context(), id)
	if err != nil {
		http.Error(w, "Attack not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}
