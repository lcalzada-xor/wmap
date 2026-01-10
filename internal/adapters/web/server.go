package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services"
)

// Server handles HTTP and WebSocket connections.
type Server struct {
	Addr             string
	Service          ports.NetworkService
	WorkspaceManager *services.WorkspaceManager
	AuthService      ports.AuthService
	AuditService     ports.AuditService
	WSManager        *WSManager
	srv              *http.Server
}

// NewServer creates a new web server.
func NewServer(addr string, service ports.NetworkService, workspaceManager *services.WorkspaceManager, authService ports.AuthService, auditService ports.AuditService) *Server {
	return &Server{
		Addr:             addr,
		Service:          service,
		WorkspaceManager: workspaceManager,
		AuthService:      authService,
		AuditService:     auditService,
		WSManager:        NewWSManager(service),
	}
}

// Run starts the server and the broadcaster.
func (s *Server) Run(ctx context.Context) error {
	// Start WS Manager
	s.WSManager.Start(ctx)

	// Setup Routes
	handler := SetupRoutes(s)

	s.srv = &http.Server{
		Addr:    s.Addr,
		Handler: handler,
	}

	// Graceful Shutdown implementation
	go func() {
		<-ctx.Done()
		log.Println("Web Server shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Web Server shutdown error: %v", err)
		}
	}()

	log.Printf("Web server listening on %s", s.Addr)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// BroadcastLog sends a log message to all connected clients
func (s *Server) BroadcastLog(message string, level string) {
	s.WSManager.BroadcastLog(message, level)
}

// BroadcastAlert sends an alert object to all connected clients
func (s *Server) BroadcastAlert(alert domain.Alert) {
	s.WSManager.BroadcastAlert(alert)
}

// handleScan triggers an active scan
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Trigger Scan
	err := s.Service.TriggerScan()
	if err != nil {
		log.Printf("Scan failed: %v", err)
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"scan_initiated"}`))
}

// Deauth Attack Handlers

// Audit Log Handler
func (s *Server) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 100
	logs, err := s.AuditService.GetLogs(r.Context(), limit)
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

// handleGetStats returns system intelligence stats
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.Service.GetSystemStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
