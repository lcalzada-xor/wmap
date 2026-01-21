package mock

import (
	"log"
	"net/http"
	"os"
)

// MockIntegration handles the integration of mock WebSocket server
type MockIntegration struct {
	mockServer *MockWebSocketServer
	scenario   string
}

// NewMockIntegration creates a new mock integration
func NewMockIntegration() *MockIntegration {
	scenario := os.Getenv("MOCK_SCENARIO")
	if scenario == "" {
		scenario = "basic"
	}

	log.Printf("Initializing Mock Integration with scenario: %s", scenario)

	return &MockIntegration{
		mockServer: NewMockWebSocketServer(scenario),
		scenario:   scenario,
	}
}

// Start starts the mock WebSocket server
func (m *MockIntegration) Start() {
	m.mockServer.Start()
	log.Printf("Mock WebSocket Server started successfully")
}

// Stop stops the mock WebSocket server
func (m *MockIntegration) Stop() {
	m.mockServer.Stop()
	log.Printf("Mock WebSocket Server stopped")
}

// GetWebSocketHandler returns the WebSocket handler for routing
func (m *MockIntegration) GetWebSocketHandler() http.HandlerFunc {
	return m.mockServer.HandleWebSocket
}

// GetScenario returns the current scenario
func (m *MockIntegration) GetScenario() string {
	return m.scenario
}
