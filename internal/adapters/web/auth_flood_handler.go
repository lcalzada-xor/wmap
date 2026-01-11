package web

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func (s *Server) handleAuthFloodStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetBSSID      string `json:"target_bssid"`
		Interface        string `json:"interface"`
		Channel          int    `json:"channel"`
		PacketCount      int    `json:"packet_count"`
		PacketIntervalMs int    `json:"packet_interval_ms"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.TargetBSSID == "" {
		http.Error(w, "target_bssid is required", http.StatusBadRequest)
		return
	}

	config := domain.AuthFloodAttackConfig{
		TargetBSSID:    req.TargetBSSID,
		Interface:      req.Interface,
		Channel:        req.Channel,
		PacketCount:    req.PacketCount,
		PacketInterval: time.Duration(req.PacketIntervalMs) * time.Millisecond,
	}

	attackID, err := s.Service.StartAuthFloodAttack(config)
	if err != nil {
		log.Printf("[AUTH API] Failed to start attack: %v", err)
		http.Error(w, "Failed to start attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUTH API] Started auth flood %s for %s", attackID, req.TargetBSSID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attack_id": attackID,
		"status":    "started",
	})
}

func (s *Server) handleAuthFloodStop(w http.ResponseWriter, r *http.Request) {
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

	if err := s.Service.StopAuthFloodAttack(attackID, force); err != nil {
		log.Printf("[AUTH API] Failed to stop attack %s: %v", attackID, err)
		http.Error(w, "Failed to stop attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "stopped",
		"message": "Attack stopped successfully",
	})
}

func (s *Server) handleAuthFloodStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attackID := r.URL.Query().Get("id")
	if attackID == "" {
		http.Error(w, "attack id is required", http.StatusBadRequest)
		return
	}

	status, err := s.Service.GetAuthFloodStatus(attackID)
	if err != nil {
		http.Error(w, "Attack not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
