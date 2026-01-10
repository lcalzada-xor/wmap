package web

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func (s *Server) handleDeauthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetMAC           string `json:"target_mac"`
		ClientMAC           string `json:"client_mac,omitempty"`
		AttackType          string `json:"attack_type"`
		PacketCount         int    `json:"packet_count"`
		PacketIntervalMs    int    `json:"packet_interval_ms"`
		ReasonCode          uint16 `json:"reason_code"`
		Channel             int    `json:"channel"`
		LegalAcknowledgment bool   `json:"legal_acknowledgment"`
		Interface           string `json:"interface"` // Added
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate legal acknowledgment
	if !req.LegalAcknowledgment {
		http.Error(w, "Legal acknowledgment required", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.TargetMAC == "" {
		http.Error(w, "target_mac is required", http.StatusBadRequest)
		return
	}

	// Convert attack type
	var attackType domain.DeauthType
	switch req.AttackType {
	case "broadcast":
		attackType = domain.DeauthBroadcast
	case "unicast":
		attackType = domain.DeauthUnicast
	case "targeted":
		attackType = domain.DeauthTargeted
	default:
		http.Error(w, "Invalid attack_type", http.StatusBadRequest)
		return
	}

	// Create attack config
	config := domain.DeauthAttackConfig{
		TargetMAC:      req.TargetMAC,
		ClientMAC:      req.ClientMAC,
		AttackType:     attackType,
		PacketCount:    req.PacketCount,
		PacketInterval: time.Duration(req.PacketIntervalMs) * time.Millisecond,
		ReasonCode:     req.ReasonCode,
		Channel:        req.Channel,
		Interface:      req.Interface,
	}

	// Start attack
	attackID, err := s.Service.StartDeauthAttack(config)
	if err != nil {
		log.Printf("[DEAUTH API] Failed to start attack: %v", err)
		http.Error(w, "Failed to start attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[DEAUTH API] Started attack %s for target %s", attackID, req.TargetMAC)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attack_id": attackID,
		"status":    "started",
		"message":   "Deauth attack initiated successfully",
	})
}

func (s *Server) handleDeauthStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attackID := r.URL.Query().Get("id")
	if attackID == "" {
		http.Error(w, "attack id is required", http.StatusBadRequest)
		return
	}

	if err := s.Service.StopDeauthAttack(attackID); err != nil {
		log.Printf("[DEAUTH API] Failed to stop attack %s: %v", attackID, err)
		http.Error(w, "Failed to stop attack: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[DEAUTH API] Stopped attack %s", attackID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "stopped",
		"message": "Attack stopped successfully",
	})
}

func (s *Server) handleDeauthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attackID := r.URL.Query().Get("id")
	if attackID == "" {
		http.Error(w, "attack id is required", http.StatusBadRequest)
		return
	}

	status, err := s.Service.GetDeauthStatus(attackID)
	if err != nil {
		http.Error(w, "Attack not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleDeauthList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attacks := s.Service.ListDeauthAttacks()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attacks": attacks,
	})
}
