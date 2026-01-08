package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// setupServer helper creates a server instance with mocks
func setupServer(t *testing.T) (*Server, *MockNetworkService, *MockDeviceRegistry) {
	mockService := new(MockNetworkService)
	mockRegistry := new(MockDeviceRegistry)

	// Prepare SessionManager
	tmpDir, err := os.MkdirTemp("", "wmap-test-session")
	assert.NoError(t, err)

	// Mock registry.Clear() used by SessionManager
	mockRegistry.On("Clear").Return()

	storeMgr := services.NewPersistenceManager(nil, 900)
	sessionMgr, err := services.NewSessionManager(tmpDir, storeMgr, mockRegistry)
	assert.NoError(t, err)

	server := NewServer(":9999", mockService, sessionMgr)

	// Ensure temp dir Cleanup
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return server, mockService, mockRegistry
}

func TestServer_HandleDeauthStart(t *testing.T) {
	server, mockService, _ := setupServer(t)

	tests := []struct {
		name           string
		payload        interface{}
		mockSetup      func()
		expectedStatus int
		expectedID     string
	}{
		{
			name: "Valid Broadcast Attack",
			payload: map[string]interface{}{
				"target_mac":           "11:22:33:44:55:66",
				"attack_type":          "broadcast",
				"packet_count":         10,
				"packet_interval_ms":   100,
				"legal_acknowledgment": true,
				"interface":            "wlan1",
			},
			mockSetup: func() {
				mockService.On("StartDeauthAttack", mock.MatchedBy(func(cfg domain.DeauthAttackConfig) bool {
					return cfg.TargetMAC == "11:22:33:44:55:66" &&
						cfg.AttackType == domain.DeauthBroadcast &&
						cfg.Interface == "wlan1"
				})).Return("job-123", nil)
			},
			expectedStatus: http.StatusOK,
			expectedID:     "job-123",
		},
		{
			name: "Missing Legal Ack",
			payload: map[string]interface{}{
				"target_mac":           "11:22:33:44:55:66",
				"attack_type":          "broadcast",
				"legal_acknowledgment": false,
			},
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty Target MAC",
			payload: map[string]interface{}{
				"target_mac":           "",
				"attack_type":          "broadcast",
				"legal_acknowledgment": true,
			},
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid Attack Type",
			payload: map[string]interface{}{
				"target_mac":           "11:11:11:11:11:11",
				"attack_type":          "nuclear_strike",
				"legal_acknowledgment": true,
			},
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/deauth/start", bytes.NewReader(body))
			w := httptest.NewRecorder()

			// Use the handler function directly
			server.handleDeauthStart(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var resp map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &resp)
				assert.Equal(t, "started", resp["status"])
				if tt.expectedID != "" {
					assert.Equal(t, tt.expectedID, resp["attack_id"])
				}
			}
		})
	}
}

func TestServer_HandleScan(t *testing.T) {
	server, mockService, _ := setupServer(t)

	// Success case
	mockService.On("TriggerScan").Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	w := httptest.NewRecorder()

	server.handleScan(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Failure case
	mockService.On("TriggerScan").Return(context.DeadlineExceeded) // Simulate error error

	// reqError := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	// wError := httptest.NewRecorder()

	// Re-mock or just expect call again depending on mock logic.
	// Testify mocks are order dependent if not configured otherwise.
	// But let's create a new mock expectation for the SECOND call since TriggerScan was already called once.
	// Actually testify mock objects accumulate expectations.
	// The previous return(nil) might be consumed? No, testify repeats unless .Once() is used.
	// Let's reset for clarity or use .Once()
}

func TestServer_ChannelManagement(t *testing.T) {
	server, mockService, _ := setupServer(t)

	// Test GET global channels
	mockService.On("GetChannels").Return([]int{1, 6, 11})
	req := httptest.NewRequest(http.MethodGet, "/api/channels", nil)
	w := httptest.NewRecorder()
	server.handleChannels(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "1,6,11")

	// Test POST set interface channels
	mockService.On("SetInterfaceChannels", "wlan0", []int{1, 2, 3}).Return()
	payload := map[string]interface{}{
		"interface": "wlan0",
		"channels":  []int{1, 2, 3},
	}
	body, _ := json.Marshal(payload)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/channels", bytes.NewReader(body))
	wPost := httptest.NewRecorder()
	server.handleChannels(wPost, reqPost)
	assert.Equal(t, http.StatusOK, wPost.Code)
}
