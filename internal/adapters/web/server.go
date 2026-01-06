package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Allow any origin for simplicity in this demo, realistically restrict this.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Server handles HTTP and WebSocket connections.
type Server struct {
	Addr           string
	Service        ports.NetworkService
	SessionManager *services.SessionManager
	Clients        map[*websocket.Conn]bool
	mu             sync.Mutex
	srv            *http.Server
}

// NewServer creates a new web server.
func NewServer(addr string, service ports.NetworkService, sessionManager *services.SessionManager) *Server {
	return &Server{
		Addr:           addr,
		Service:        service,
		SessionManager: sessionManager,
		Clients:        make(map[*websocket.Conn]bool),
	}
}

// Run starts the server and the broadcaster.
func (s *Server) Run(ctx context.Context) error {
	// TODO: Make this path configurable or use embed
	http.Handle("/", http.FileServer(http.Dir("./internal/adapters/web/static")))
	http.HandleFunc("/ws", s.handleWebSocket)
	http.HandleFunc("/api/scan", s.handleScan)
	http.HandleFunc("/api/export", s.handleExport)
	http.HandleFunc("/api/config", s.handleGetConfig)
	http.HandleFunc("/api/config/persistence", s.handleTogglePersistence)
	http.HandleFunc("/api/session/clear", s.handleSessionClear)
	http.HandleFunc("/api/sessions", s.handleListSessions)
	http.HandleFunc("/api/sessions/new", s.handleCreateSession)
	http.HandleFunc("/api/sessions/load", s.handleLoadSession)
	http.HandleFunc("/api/session/status", s.handleSessionStatus)
	http.HandleFunc("/api/channels", s.handleChannels)
	http.HandleFunc("/api/interfaces", s.handleListInterfaces)

	// Deauth Attack endpoints
	http.HandleFunc("/api/deauth/start", s.handleDeauthStart)
	http.HandleFunc("/api/deauth/stop", s.handleDeauthStop)
	http.HandleFunc("/api/deauth/status", s.handleDeauthStatus)
	http.HandleFunc("/api/deauth/list", s.handleDeauthList)

	http.Handle("/metrics", promhttp.Handler())

	s.srv = &http.Server{
		Addr:    s.Addr,
		Handler: nil, // Use DefaultServeMux
	}

	// Start broadcaster in a goroutine
	go s.processAndBroadcast(ctx)

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

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}

	s.mu.Lock()
	s.Clients[conn] = true
	s.mu.Unlock()

	// Clean up on disconnect
	// We don't read from client in this app, but we need to keep connection open handling Close
	go func() {
		defer conn.Close()
		defer func() {
			s.mu.Lock()
			delete(s.Clients, conn)
			s.mu.Unlock()
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

func (s *Server) processAndBroadcast(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second) // "Sweep" every 2 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.broadcastGraph()
		}
	}
}

func (s *Server) broadcastGraph() {
	// Get Data from Service (Decoupled)
	graphData := s.Service.GetGraph()

	data, err := json.Marshal(graphData)
	if err != nil {
		log.Println("JSON marshal error:", err)
		return
	}

	s.mu.Lock()
	for conn := range s.Clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Println("Write error:", err)
			conn.Close()
			delete(s.Clients, conn)
		}
	}
	s.mu.Unlock()
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

// handleExport exports devices or alerts in various formats
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	dataType := r.URL.Query().Get("type")
	if dataType == "" {
		dataType = "devices"
	}

	// Handle alerts export
	if dataType == "alerts" {
		alerts := s.Service.GetAlerts()
		s.exportAlerts(w, alerts, format)
		return
	}

	// Export devices - convert from GraphData
	graphData := s.Service.GetGraph()
	devices := make([]domain.Device, 0)

	for _, node := range graphData.Nodes {
		if node.Group == "network" {
			continue
		}
		device := domain.Device{
			MAC:      node.MAC,
			Type:     node.Group,
			Vendor:   node.Vendor,
			RSSI:     node.RSSI,
			Security: node.Security,
			Standard: node.Standard,
			Model:    node.Model,
			LastSeen: node.LastSeen,
		}
		devices = append(devices, device)
	}

	s.exportDevices(w, devices, format)
}

func (s *Server) exportDevices(w http.ResponseWriter, devices []domain.Device, format string) {
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_devices.csv")
		if err := services.ExportCSV(w, devices); err != nil {
			log.Printf("CSV export error: %v", err)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_devices.json")
		if err := services.ExportJSON(w, devices); err != nil {
			log.Printf("JSON export error: %v", err)
		}
	}
}

func (s *Server) exportAlerts(w http.ResponseWriter, alerts []domain.Alert, format string) {
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_alerts.csv")
		if err := services.ExportAlertsCSV(w, alerts); err != nil {
			log.Printf("CSV export error: %v", err)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=wmap_alerts.json")
		if err := services.ExportAlertsJSON(w, alerts); err != nil {
			log.Printf("JSON export error: %v", err)
		}
	}
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"persistenceEnabled": s.Service.IsPersistenceEnabled(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *Server) handleTogglePersistence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabledStr := r.URL.Query().Get("enabled")
	enabled := enabledStr == "true"
	s.Service.SetPersistenceEnabled(enabled)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"persistence_updated","enabled":%v}`, enabled)
}

func (s *Server) handleSessionClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.Service.ResetSession()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"session_cleared"}`))
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		iface := r.URL.Query().Get("interface")
		var channels []int
		if iface != "" {
			channels = s.Service.GetInterfaceChannels(iface)
		} else {
			// Fallback or Global
			channels = s.Service.GetChannels()
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

		if req.Interface != "" {
			s.Service.SetInterfaceChannels(req.Interface, req.Channels)
		} else {
			s.Service.SetChannels(req.Channels)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"channels_updated"}`))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Use new detailed method
	details := s.Service.GetInterfaceDetails()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces": details,
	})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessions, err := s.SessionManager.ListSessions()
	if err != nil {
		http.Error(w, "Failed to list sessions", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"sessions": sessions})
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if err := s.SessionManager.CreateSession(req.Name); err != nil {
		http.Error(w, "Failed to create session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"created"}`))
}

func (s *Server) handleLoadSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if err := s.SessionManager.LoadSession(req.Name); err != nil {
		http.Error(w, "Failed to load session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"loaded"}`))
}

func (s *Server) handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	current := s.SessionManager.GetCurrentSession()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"currentSession": current,
	})
}

// Deauth Attack Handlers

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
