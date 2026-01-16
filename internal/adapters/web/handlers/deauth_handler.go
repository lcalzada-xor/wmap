package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// DeauthHandler handles deauthentication attacks
type DeauthHandler struct {
	Service ports.NetworkService
}

// NewDeauthHandler creates a new DeauthHandler
func NewDeauthHandler(service ports.NetworkService) *DeauthHandler {
	return &DeauthHandler{
		Service: service,
	}
}

// HandleStart triggers a new deauth attack
func (h *DeauthHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req struct {
		TargetMAC           string `json:"target_mac"`
		ClientMAC           string `json:"client_mac,omitempty"`
		AttackType          string `json:"attack_type"`
		PacketCount         int    `json:"packet_count"`
		PacketIntervalMs    int    `json:"packet_interval_ms"`
		ReasonCode          uint16 `json:"reason_code"`
		Channel             int    `json:"channel"`
		LegalAcknowledgment bool   `json:"legal_acknowledgment"`
		Interface           string `json:"interface"`
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
	if !domain.IsValidMAC(req.TargetMAC) {
		http.Error(w, "Invalid target_mac", http.StatusBadRequest)
		return
	}
	if req.ClientMAC != "" && !domain.IsValidMAC(req.ClientMAC) {
		http.Error(w, "Invalid client_mac", http.StatusBadRequest)
		return
	}
	if req.Interface != "" && !domain.IsValidInterface(req.Interface) {
		http.Error(w, "Invalid interface name", http.StatusBadRequest)
		return
	}

	if req.PacketCount < 0 || req.PacketIntervalMs < 0 {
		http.Error(w, "Packet count and interval must be non-negative", http.StatusBadRequest)
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
	attackID, err := h.Service.StartDeauthAttack(r.Context(), config)
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

// HandleStop stops an ongoing attack
func (h *DeauthHandler) HandleStop(w http.ResponseWriter, r *http.Request) {
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

	if err := h.Service.StopDeauthAttack(attackID, force); err != nil {
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

// HandleStatus returns the status of an attack
func (h *DeauthHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attackID := r.URL.Query().Get("id")
	if attackID == "" {
		http.Error(w, "attack id is required", http.StatusBadRequest)
		return
	}

	status, err := h.Service.GetDeauthStatus(attackID)
	if err != nil {
		http.Error(w, "Attack not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// HandleList returns list of active attacks
func (h *DeauthHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attacks := h.Service.ListDeauthAttacks()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attacks": attacks,
	})
}
