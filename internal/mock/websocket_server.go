package mock

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in mock mode
	},
}

// MockWebSocketServer simulates real-time WiFi data
type MockWebSocketServer struct {
	generator *DataGenerator
	clients   map[*websocket.Conn]bool
	mu        sync.Mutex
	scenario  string
	running   bool
}

// NewMockWebSocketServer creates a new mock WebSocket server
func NewMockWebSocketServer(scenario string) *MockWebSocketServer {
	gen := NewDataGenerator()
	gen.GenerateScenario(scenario)

	return &MockWebSocketServer{
		generator: gen,
		clients:   make(map[*websocket.Conn]bool),
		scenario:  scenario,
		running:   false,
	}
}

// HandleWebSocket handles WebSocket connections
func (s *MockWebSocketServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	log.Printf("Mock WebSocket client connected (total: %d)", len(s.clients))

	// Send initial graph data immediately
	s.sendGraphUpdate(conn)

	// Handle incoming messages (commands from frontend)
	go s.handleClientMessages(conn)

	// Keep connection alive
	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		conn.Close()
		log.Printf("Mock WebSocket client disconnected (remaining: %d)", len(s.clients))
	}()

	// Wait for connection to close
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// Start begins sending periodic updates
func (s *MockWebSocketServer) Start() {
	if s.running {
		return
	}
	s.running = true

	log.Printf("Mock WebSocket Server started with scenario: %s", s.scenario)

	// Send graph updates every 3-5 seconds
	go func() {
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()

		for s.running {
			<-ticker.C
			s.generator.SimulateActivity()
			s.broadcastGraphUpdate()
		}
	}()

	// Send random events every 5-10 seconds
	go func() {
		for s.running {
			time.Sleep(time.Duration(5+rand.Intn(5)) * time.Second)
			s.sendRandomEvent()
		}
	}()

	// Send random logs every 2-4 seconds
	go func() {
		for s.running {
			time.Sleep(time.Duration(2+rand.Intn(2)) * time.Second)
			s.sendRandomLog()
		}
	}()
}

// Stop stops the mock server
func (s *MockWebSocketServer) Stop() {
	s.running = false
}

// broadcastGraphUpdate sends graph data to all clients
func (s *MockWebSocketServer) broadcastGraphUpdate() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for client := range s.clients {
		s.sendGraphUpdate(client)
	}
}

// sendGraphUpdate sends current graph state to a client
func (s *MockWebSocketServer) sendGraphUpdate(conn *websocket.Conn) {
	nodes := s.convertToNodes()
	edges := s.convertToEdges()

	msg := map[string]interface{}{
		"type": "graph",
		"payload": map[string]interface{}{
			"nodes": nodes,
			"edges": edges,
		},
	}

	data, _ := json.Marshal(msg)
	conn.WriteMessage(websocket.TextMessage, data)
}

// convertToNodes converts mock devices to frontend node format
func (s *MockWebSocketServer) convertToNodes() []map[string]interface{} {
	devices := s.generator.GetDevices()
	nodes := make([]map[string]interface{}, 0, len(devices))

	for _, device := range devices {
		node := map[string]interface{}{
			"id":    device.MAC,
			"label": device.SSID,
			"mac":   device.MAC,
			"type":  device.Type,
			"rssi":  device.RSSI,
		}

		if device.Type == "AP" {
			node["ssid"] = device.SSID
			node["channel"] = device.Channel
			node["security"] = device.Security
			node["wps"] = device.WPS
			node["hidden"] = device.Hidden
			node["frequency"] = device.Frequency
			node["hasHandshake"] = device.HasHandshake
			node["group"] = NodeGroups.AP
		} else {
			node["deviceName"] = device.DeviceName
			node["connected"] = device.Connected
			node["connectedTo"] = device.ConnectedTo
			if device.Connected {
				node["label"] = device.DeviceName
			} else {
				node["label"] = "Probing: " + device.DeviceName
			}
			node["group"] = NodeGroups.STA
		}

		node["vendor"] = device.Vendor
		node["lastSeen"] = device.LastSeen.Format(time.RFC3339)
		node["packets"] = device.PacketCount

		nodes = append(nodes, node)
	}

	return nodes
}

// convertToEdges creates edges between stations and APs
func (s *MockWebSocketServer) convertToEdges() []map[string]interface{} {
	edges := make([]map[string]interface{}, 0)

	for _, sta := range s.generator.GetStations() {
		if sta.Connected && sta.ConnectedTo != "" {
			edge := map[string]interface{}{
				"from":  sta.MAC,
				"to":    sta.ConnectedTo,
				"type":  "connection",
				"label": "Connected",
			}
			edges = append(edges, edge)
		}
	}

	return edges
}

// sendRandomEvent sends a random event (alert, handshake, etc.)
func (s *MockWebSocketServer) sendRandomEvent() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.clients) == 0 {
		return
	}

	eventType := rand.Intn(3)
	var msg map[string]interface{}

	switch eventType {
	case 0:
		// Handshake captured
		aps := s.generator.GetAPs()
		if len(aps) > 0 {
			ap := aps[rand.Intn(len(aps))]
			ap.HasHandshake = true

			msg = map[string]interface{}{
				"type": "alert",
				"payload": map[string]interface{}{
					"type":    "HANDSHAKE_CAPTURED",
					"details": fmt.Sprintf("SSID: %s, BSSID: %s", ap.SSID, ap.MAC),
				},
			}
		}

	case 1:
		// Vulnerability detected
		msg = map[string]interface{}{
			"type": "vulnerability:new",
			"payload": map[string]interface{}{
				"type":        "WPS_VULNERABLE",
				"severity":    "high",
				"description": "WPS PIN attack possible",
			},
		}

	case 2:
		// Security anomaly
		msg = map[string]interface{}{
			"type": "alert",
			"payload": map[string]interface{}{
				"type":    "ANOMALY",
				"message": "Suspicious deauthentication frames detected",
			},
		}
	}

	if msg != nil {
		data, _ := json.Marshal(msg)
		for client := range s.clients {
			client.WriteMessage(websocket.TextMessage, data)
		}
	}
}

// sendRandomLog sends a random log message
func (s *MockWebSocketServer) sendRandomLog() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.clients) == 0 {
		return
	}

	logMessages := []string{
		"Scanning channel %d...",
		"New device detected: %s",
		"Signal strength updated for %s",
		"Packet capture rate: %d pkt/s",
		"Channel hop completed",
		"Monitoring %d networks",
	}

	levels := []string{"info", "success", "warning"}
	message := logMessages[rand.Intn(len(logMessages))]

	// Format message with random data
	switch rand.Intn(3) {
	case 0:
		message = fmt.Sprintf(message, rand.Intn(13)+1)
	case 1:
		devices := s.generator.GetDevices()
		if len(devices) > 0 {
			device := devices[rand.Intn(len(devices))]
			message = fmt.Sprintf(message, device.MAC)
		}
	case 2:
		message = fmt.Sprintf(message, rand.Intn(100)+50)
	}

	msg := map[string]interface{}{
		"type": "log",
		"payload": map[string]interface{}{
			"message": message,
			"level":   levels[rand.Intn(len(levels))],
		},
	}

	data, _ := json.Marshal(msg)
	for client := range s.clients {
		client.WriteMessage(websocket.TextMessage, data)
	}
}

// handleClientMessages handles commands from the frontend
func (s *MockWebSocketServer) handleClientMessages(conn *websocket.Conn) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var cmd map[string]interface{}
		if err := json.Unmarshal(message, &cmd); err != nil {
			continue
		}

		// Handle different command types
		cmdType, ok := cmd["type"].(string)
		if !ok {
			continue
		}

		switch cmdType {
		case "start_deauth":
			s.handleStartDeauth(conn, cmd)
		case "stop_deauth":
			s.handleStopDeauth(conn, cmd)
		case "start_wps":
			s.handleStartWPS(conn, cmd)
		case "stop_wps":
			s.handleStopWPS(conn, cmd)
		}
	}
}

// Mock attack handlers
func (s *MockWebSocketServer) handleStartDeauth(conn *websocket.Conn, cmd map[string]interface{}) {
	// Simulate deauth attack start
	response := map[string]interface{}{
		"type": "log",
		"payload": map[string]interface{}{
			"message": "Deauth attack started (MOCK)",
			"level":   "warning",
		},
	}
	data, _ := json.Marshal(response)
	conn.WriteMessage(websocket.TextMessage, data)
}

func (s *MockWebSocketServer) handleStopDeauth(conn *websocket.Conn, cmd map[string]interface{}) {
	response := map[string]interface{}{
		"type": "log",
		"payload": map[string]interface{}{
			"message": "Deauth attack stopped (MOCK)",
			"level":   "info",
		},
	}
	data, _ := json.Marshal(response)
	conn.WriteMessage(websocket.TextMessage, data)
}

func (s *MockWebSocketServer) handleStartWPS(conn *websocket.Conn, cmd map[string]interface{}) {
	// Simulate WPS attack with periodic updates
	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(2 * time.Second)
			msg := map[string]interface{}{
				"type": "wps.log",
				"payload": map[string]interface{}{
					"message": fmt.Sprintf("WPS PIN attempt %d/5 (MOCK)", i+1),
					"level":   "info",
				},
			}
			data, _ := json.Marshal(msg)
			conn.WriteMessage(websocket.TextMessage, data)
		}

		// Final status
		finalMsg := map[string]interface{}{
			"type": "wps.status",
			"payload": map[string]interface{}{
				"status":  "completed",
				"message": "WPS attack completed (MOCK)",
			},
		}
		data, _ := json.Marshal(finalMsg)
		conn.WriteMessage(websocket.TextMessage, data)
	}()
}

func (s *MockWebSocketServer) handleStopWPS(conn *websocket.Conn, cmd map[string]interface{}) {
	response := map[string]interface{}{
		"type": "wps.status",
		"payload": map[string]interface{}{
			"status":  "stopped",
			"message": "WPS attack stopped (MOCK)",
		},
	}
	data, _ := json.Marshal(response)
	conn.WriteMessage(websocket.TextMessage, data)
}

// NodeGroups constants (matching frontend)
var NodeGroups = struct {
	AP  string
	STA string
}{
	AP:  "ap",
	STA: "sta",
}
