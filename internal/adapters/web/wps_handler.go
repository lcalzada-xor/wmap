package web

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// handleStartWPSAttack triggers a new Pixie Dust attack
func (s *Server) handleStartWPSAttack(w http.ResponseWriter, r *http.Request) {
	var config domain.WPSAttackConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	id, err := s.Service.StartWPSAttack(config)
	if err != nil {
		http.Error(w, "Failed to start attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "started"})
}

// handleStopWPSAttack stops an ongoing attack
func (s *Server) handleStopWPSAttack(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := s.Service.StopWPSAttack(id); err != nil {
		http.Error(w, "Failed to stop attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// handleGetWPSStatus returns the status of an attack
func (s *Server) handleGetWPSStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	status, err := s.Service.GetWPSStatus(id)
	if err != nil {
		http.Error(w, "Attack not found: "+err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}
