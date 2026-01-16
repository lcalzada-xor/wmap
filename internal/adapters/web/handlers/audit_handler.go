package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// AuditHandler handles audit logging operations
type AuditHandler struct {
	Service ports.AuditService
}

// NewAuditHandler creates a new AuditHandler
func NewAuditHandler(service ports.AuditService) *AuditHandler {
	return &AuditHandler{
		Service: service,
	}
}

// HandleGetLogs returns audit logs
func (h *AuditHandler) HandleGetLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 100
	logs, err := h.Service.GetLogs(r.Context(), limit)
	if err != nil {
		log.Printf("Failed to fetch audit logs: %v", err)
		http.Error(w, "Failed to fetch logs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": logs,
	})
}
