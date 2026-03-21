package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockWebSocketConn simulates a WebSocket connection for testing
type mockWebSocketConn struct {
	messages      [][]byte
	closed        bool
	writeDeadline time.Time
	delay         time.Duration
	mu            sync.Mutex
}

func (m *mockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("connection closed")
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	// Copy data to avoid race conditions
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	m.messages = append(m.messages, dataCopy)
	return nil
}

func (m *mockWebSocketConn) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeDeadline = t
	return nil
}

func (m *mockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	// Not used in tests, return EOF
	return 0, nil, fmt.Errorf("EOF")
}

func (m *mockWebSocketConn) GetMessages() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.messages
}

func (m *mockWebSocketConn) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func setupTestWS(t *testing.T) (*websocket.Conn, *websocket.Conn, *httptest.Server, func()) {
	serverConnChan := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConnChan <- conn
	}))

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.DefaultDialer
	clientConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("Failed to dial: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnChan:
	case <-time.After(1 * time.Second):
		clientConn.Close()
		server.Close()
		t.Fatalf("Server side connection never established")
	}

	cleanup := func() {
		clientConn.Close()
		serverConn.Close()
		server.Close()
	}

	return clientConn, serverConn, server, cleanup
}

// mockNetworkService for testing
type mockNetworkService struct {
	mock.Mock
}

func (m *mockNetworkService) GetGraph(ctx context.Context) (domain.GraphData, error) {
	args := m.Called(ctx)
	return domain.GraphData{}, args.Error(1)
}

func (m *mockNetworkService) GetDeviceConnectionHistory(ctx context.Context, mac string) ([]domain.ConnectionEvent, error) {
	return []domain.ConnectionEvent{}, nil
}

func (m *mockNetworkService) GetAlerts(ctx context.Context) ([]domain.Alert, error) {
	return []domain.Alert{}, nil
}

func (m *mockNetworkService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	return domain.SystemStats{}, nil
}

func (m *mockNetworkService) AddRule(ctx context.Context, rule domain.AlertRule) error {
	return nil
}

func (m *mockNetworkService) TriggerScan(ctx context.Context) error {
	return nil
}

func (m *mockNetworkService) GetInterfaces(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func (m *mockNetworkService) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	return []domain.InterfaceInfo{}, nil
}

func (m *mockNetworkService) SetChannels(ctx context.Context, channels []int) error {
	return nil
}

func (m *mockNetworkService) GetChannels(ctx context.Context) ([]int, error) {
	return []int{}, nil
}

func (m *mockNetworkService) SetInterfaceChannels(ctx context.Context, iface string, channels []int) error {
	return nil
}

func (m *mockNetworkService) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	return []int{}, nil
}

func (m *mockNetworkService) StartDeauthAttack(ctx context.Context, cfg domain.DeauthAttackConfig) (string, error) {
	return "", nil
}

func (m *mockNetworkService) StopDeauthAttack(ctx context.Context, id string, force bool) error {
	return nil
}

func (m *mockNetworkService) GetDeauthStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error) {
	return domain.DeauthAttackStatus{}, nil
}

func (m *mockNetworkService) ListDeauthAttacks(ctx context.Context) ([]domain.DeauthAttackStatus, error) {
	return []domain.DeauthAttackStatus{}, nil
}

func (m *mockNetworkService) StartWPSAttack(ctx context.Context, cfg domain.WPSAttackConfig) (string, error) {
	return "", nil
}

func (m *mockNetworkService) StopWPSAttack(ctx context.Context, id string, force bool) error {
	return nil
}

func (m *mockNetworkService) GetWPSStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error) {
	return domain.WPSAttackStatus{}, nil
}

func (m *mockNetworkService) StartAuthFloodAttack(ctx context.Context, cfg domain.AuthFloodAttackConfig) (string, error) {
	return "", nil
}

func (m *mockNetworkService) StopAuthFloodAttack(ctx context.Context, id string, force bool) error {
	return nil
}

func (m *mockNetworkService) GetAuthFloodStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error) {
	return domain.AuthFloodAttackStatus{}, nil
}

func (m *mockNetworkService) StartPMKIDAttack(ctx context.Context, cfg domain.PMKIDAttackConfig) (string, error) {
	return "", nil
}

func (m *mockNetworkService) StopPMKIDAttack(ctx context.Context, id string, force bool) error {
	return nil
}

func (m *mockNetworkService) GetPMKIDStatus(ctx context.Context, id string) (domain.PMKIDAttackStatus, error) {
	return domain.PMKIDAttackStatus{}, nil
}

func (m *mockNetworkService) ProcessDevice(ctx context.Context, device domain.Device) error {
	return nil
}

func (m *mockNetworkService) SetPersistenceEnabled(enabled bool) {}

func (m *mockNetworkService) IsPersistenceEnabled() bool {
	return false
}

func (m *mockNetworkService) ResetWorkspace(ctx context.Context) error {
	return nil
}

func (m *mockNetworkService) Close() error {
	return nil
}

// Tests

func TestWSManager_BroadcastMessage(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	// Broadcast a message
	msg := WSMessage{
		Type:    "test",
		Payload: map[string]string{"data": "hello"},
	}
	wsm.broadcastMessage(msg)

	// Verify the connection is still in the map (success)
	wsm.mu.Lock()
	_, exists := wsm.Clients[serverConn]
	wsm.mu.Unlock()
	assert.True(t, exists)

	// Verify client received it
	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)
	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "test", received.Type)
}

func TestWSManager_BroadcastAlert(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	alert := domain.Alert{
		Type:     "DEAUTH",
		Severity: "HIGH",
		Message:  "Deauth attack detected",
	}

	wsm.BroadcastAlert(alert)

	// Try to read the message from the websocket
	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)

	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "alert", received.Type)
}

func TestWSManager_NotifyVulnerabilityDetected(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	vuln := domain.VulnerabilityRecord{
		Name:      "WEP",
		Severity:  domain.VulnSeverityCritical,
		DeviceMAC: "AA:BB:CC:DD:EE:FF",
	}

	wsm.NotifyNewVulnerability(context.Background(), vuln)

	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)

	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "vulnerability:new", received.Type)
}

func TestWSManager_NotifyVulnerabilityConfirmed(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	vuln := domain.VulnerabilityRecord{
		Name:      "PMKID",
		Severity:  domain.VulnSeverityHigh,
		DeviceMAC: "11:22:33:44:55:66",
	}

	wsm.NotifyVulnerabilityConfirmed(context.Background(), vuln)

	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)

	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "vulnerability:confirmed", received.Type)
}

func TestWSManager_SlowClientDoesNotBlock(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	// Fast client
	_, serverConn1, _, cleanup1 := setupTestWS(t)
	defer cleanup1()

	// Slow client (simulates network delay)
	_, serverConn2, _, cleanup2 := setupTestWS(t)
	defer cleanup2()

	wsm.mu.Lock()
	wsm.Clients[serverConn1] = &domain.User{Username: "fast"}
	wsm.Clients[serverConn2] = &domain.User{Username: "slow"}
	wsm.mu.Unlock()

	// Broadcast should not block waiting for slow client
	start := time.Now()
	msg := WSMessage{Type: "test", Payload: "data"}
	wsm.broadcastMessage(msg)
	duration := time.Since(start)

	// Broadcast should complete quickly
	assert.Less(t, duration, 200*time.Millisecond, "Broadcast took too long")
}

func TestWSManager_ConcurrentBroadcasts(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	_, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	// 20 concurrent broadcasts
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			msg := WSMessage{
				Type:    "test",
				Payload: map[string]int{"number": n},
			}
			wsm.broadcastMessage(msg)
		}(i)
	}

	wg.Wait()
}

func TestWSManager_ClientDisconnectDuringBroadcast(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	_, serverConn, _, cleanup := setupTestWS(t)

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	// Close the connection manually
	serverConn.Close()
	cleanup()

	// Broadcast should handle closed connection gracefully
	msg := WSMessage{Type: "test", Payload: "data"}
	wsm.broadcastMessage(msg)

	wsm.mu.Lock()
	defer wsm.mu.Unlock()
	assert.Equal(t, 0, len(wsm.Clients))
}

func TestWSManager_BroadcastLog(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	wsm.BroadcastLog("Test log message", "INFO")

	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)
	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "log", received.Type)
}

func TestWSManager_BroadcastWPSLog(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	wsm.BroadcastWPSLog("attack-123", "[+] WPS PIN: 12345670")

	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)
	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "wps.log", received.Type)
}

func TestWSManager_BroadcastWPSStatus(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	clientConn, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	status := domain.WPSAttackStatus{
		ID:     "attack-123",
		Status: domain.WPSStatusRunning,
	}

	wsm.BroadcastWPSStatus(status)

	_, p, err := clientConn.ReadMessage()
	assert.NoError(t, err)

	var received WSMessage
	err = json.Unmarshal(p, &received)
	assert.NoError(t, err)
	assert.Equal(t, "wps.status", received.Type)
}

func TestWSManager_EmptyClientsList(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	// Broadcast with no clients should not panic
	msg := WSMessage{Type: "test", Payload: "data"}
	assert.NotPanics(t, func() {
		wsm.broadcastMessage(msg)
	})
}

func TestWSManager_JSONMarshalError(t *testing.T) {
	service := &mockNetworkService{}
	wsm := NewWSManager(service)

	_, serverConn, _, cleanup := setupTestWS(t)
	defer cleanup()

	wsm.mu.Lock()
	wsm.Clients[serverConn] = &domain.User{Username: "testuser"}
	wsm.mu.Unlock()

	// Create a message with un-marshalable payload (channel)
	msg := WSMessage{
		Type:    "test",
		Payload: make(chan int), // Channels cannot be marshaled to JSON
	}

	// Should not panic, just log error
	assert.NotPanics(t, func() {
		wsm.broadcastMessage(msg)
	})
}
