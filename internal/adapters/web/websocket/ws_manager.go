package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/middleware"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")

		// Allow same-origin (no Origin header)
		if origin == "" {
			return true
		}

		// Allowed origins
		allowedOrigins := []string{
			"http://localhost:8080",
			"http://127.0.0.1:8080",
			"http://[::1]:8080",
		}

		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}

		log.Printf("WebSocket: Rejected origin: %s", origin)
		return false
	},
}

type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type WSManager struct {
	Service ports.NetworkService
	Clients map[*websocket.Conn]*domain.User
	mu      sync.Mutex
}

func NewWSManager(service ports.NetworkService) *WSManager {
	return &WSManager{
		Service: service,
		Clients: make(map[*websocket.Conn]*domain.User),
	}
}

func (m *WSManager) Start(ctx context.Context) {
	go m.processAndBroadcast(ctx)
}

func (m *WSManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Extract user from context (set by AuthMiddleware)
	user, ok := r.Context().Value(middleware.UserContextKey).(*domain.User)
	if !ok || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}

	m.mu.Lock()
	m.Clients[conn] = user
	m.mu.Unlock()

	log.Printf("WebSocket connected: user=%s, role=%s", user.Username, user.Role)

	// Clean up on disconnect
	go func() {
		defer conn.Close()
		defer func() {
			m.mu.Lock()
			delete(m.Clients, conn)
			m.mu.Unlock()
			log.Printf("WebSocket disconnected: user=%s", user.Username)
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

func (m *WSManager) processAndBroadcast(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second) // "Sweep" every 2 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.broadcastGraph()
		}
	}
}

func (m *WSManager) broadcastGraph() {
	graphData, err := m.Service.GetGraph(context.Background())
	if err != nil {
		log.Println("Error getting graph:", err)
		return
	}

	msg := WSMessage{
		Type:    "graph",
		Payload: graphData,
	}
	m.broadcastMessage(msg)
}

// BroadcastLog sends a log message to all connected clients
func (m *WSManager) BroadcastLog(message string, level string) {
	payload := map[string]string{
		"message": message,
		"level":   level,
	}

	msg := WSMessage{
		Type:    "log",
		Payload: payload,
	}
	m.broadcastMessage(msg)
}

// BroadcastAlert sends an alert object to all connected clients
func (m *WSManager) BroadcastAlert(alert domain.Alert) {
	msg := WSMessage{
		Type:    "alert",
		Payload: alert,
	}
	m.broadcastMessage(msg)
}

// BroadcastWPSLog sends a WPS log line to all connected clients
func (m *WSManager) BroadcastWPSLog(attackID, line string) {
	payload := map[string]string{
		"attack_id": attackID,
		"line":      line,
	}

	msg := WSMessage{
		Type:    "wps.log",
		Payload: payload,
	}

	m.broadcastMessage(msg)
}

// BroadcastWPSStatus sends a WPS status update to all connected clients
func (m *WSManager) BroadcastWPSStatus(status domain.WPSAttackStatus) {
	msg := WSMessage{
		Type:    "wps.status",
		Payload: status,
	}

	m.broadcastMessage(msg)
}

// NotifyNewVulnerability broadcasts a new vulnerability detection.
func (m *WSManager) NotifyNewVulnerability(ctx context.Context, vuln domain.VulnerabilityRecord) {
	msg := WSMessage{
		Type:    "vulnerability:new",
		Payload: vuln,
	}
	m.broadcastMessage(msg)
}

// NotifyVulnerabilityConfirmed broadcasts a confirmed vulnerability (via active validation).
func (m *WSManager) NotifyVulnerabilityConfirmed(ctx context.Context, vuln domain.VulnerabilityRecord) {
	msg := WSMessage{
		Type:    "vulnerability:confirmed",
		Payload: vuln,
	}
	m.broadcastMessage(msg)
}

func (m *WSManager) broadcastMessage(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Println("JSON marshal error:", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for conn := range m.Clients {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			conn.Close()
			delete(m.Clients, conn)
		}
	}
}
