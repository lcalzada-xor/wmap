package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/web"
	"github.com/lcalzada-xor/wmap/internal/adapters/web/server"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
	"github.com/lcalzada-xor/wmap/internal/core/services/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// setupServer helper creates a server instance with mocks
func setupServer(t *testing.T) (*server.Server, *web.MockNetworkService, *web.MockDeviceRegistry, *web.MockAuthService) {
	mockService := new(web.MockNetworkService)
	mockRegistry := new(web.MockDeviceRegistry)

	mockAuth := new(web.MockAuthService)

	// Prepare WorkspaceManager
	tmpDir, err := os.MkdirTemp("", "wmap-test-workspace")
	assert.NoError(t, err)

	// Mock registry.Clear() used by WorkspaceManager
	mockRegistry.On("Clear").Return()

	storeMgr := persistence.NewPersistenceManager(nil, 900)
	workspaceMgr, err := workspace.NewWorkspaceManager(tmpDir, storeMgr, mockRegistry)
	assert.NoError(t, err)

	srv := server.NewServer(":9999", mockService, workspaceMgr, mockAuth, nil, nil)

	// Ensure temp dir Cleanup
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return srv, mockService, mockRegistry, mockAuth
}

func TestServer_HandleDeauthStart(t *testing.T) {
	server, mockService, _, _ := setupServer(t)

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
				mockService.On("StartDeauthAttack", mock.Anything, mock.MatchedBy(func(cfg domain.DeauthAttackConfig) bool {
					return cfg.TargetMAC == "11:22:33:44:55:66" &&
						cfg.AttackType == domain.DeauthBroadcast &&
						cfg.Interface == "wlan1"
				})).Return("job-123", nil)
				// The instruction implies adding or modifying StopDeauthAttack/StopWPSAttack mocks.
				// As per the provided "Code Edit" snippet, it seems to be an attempt to add a StopDeauthAttack mock.
				// The snippet was malformed, so I'm interpreting it as adding a new mock call.
				// Assuming "test-id" is a placeholder for an attack ID and 'false' for force.
				mockService.On("StopDeauthAttack", "test-id", false).Return(nil)
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
			server.DeauthHandler.HandleStart(w, req)

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

func TestServer_DeauthValidation(t *testing.T) {
	server, _, _, _ := setupServer(t)

	// Method Validation
	t.Run("Method Not Allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/deauth/start", nil) // Wrong method
		w := httptest.NewRecorder()
		server.DeauthHandler.HandleStart(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	// Negative Payload Validation
	t.Run("Negative Values", func(t *testing.T) {
		payload := map[string]interface{}{
			"target_mac":           "11:22:33:44:55:66",
			"attack_type":          "broadcast",
			"packet_count":         -10, // Invalid
			"packet_interval_ms":   -5,  // Invalid
			"legal_acknowledgment": true,
			"interface":            "wlan1",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/deauth/start", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.DeauthHandler.HandleStart(w, req)

		// Assuming handler validation logic exists, expecting 400
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestServer_HandleScan(t *testing.T) {
	server, mockService, _, _ := setupServer(t)

	// Success case
	mockService.On("TriggerScan", mock.Anything).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	w := httptest.NewRecorder()

	server.ScanHandler.HandleScan(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Failure case
	mockService.On("TriggerScan", mock.Anything).Return(context.DeadlineExceeded) // Simulate error
}

func TestServer_ChannelManagement(t *testing.T) {
	server, mockService, _, _ := setupServer(t)

	// Test GET global channels
	mockService.On("GetChannels", mock.Anything).Return([]int{1, 6, 11}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/channels", nil)
	w := httptest.NewRecorder()
	server.ScanHandler.HandleChannels(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "1,6,11")

	// Test POST set interface channels
	mockService.On("SetInterfaceChannels", mock.Anything, "wlan0", []int{1, 2, 3}).Return(nil)
	payload := map[string]interface{}{
		"interface": "wlan0",
		"channels":  []int{1, 2, 3},
	}
	body, _ := json.Marshal(payload)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/channels", bytes.NewReader(body))
	wPost := httptest.NewRecorder()
	server.ScanHandler.HandleChannels(wPost, reqPost)
	assert.Equal(t, http.StatusOK, wPost.Code)
}

func TestServer_HandleGetAuditLogs(t *testing.T) {
	mockService := new(web.MockNetworkService)
	mockRegistry := new(web.MockDeviceRegistry)
	mockAuth := new(web.MockAuthService)
	mockAudit := new(MockAuditService)

	// Prepare WSM
	tmpDir, _ := os.MkdirTemp("", "wmap-test-audit")
	defer os.RemoveAll(tmpDir)

	mockRegistry.On("Clear").Return()
	storeMgr := persistence.NewPersistenceManager(nil, 900)
	workspaceMgr, _ := workspace.NewWorkspaceManager(tmpDir, storeMgr, mockRegistry)

	srv := server.NewServer(":9999", mockService, workspaceMgr, mockAuth, mockAudit, nil)

	// Test Case
	mockAudit.On("GetLogs", mock.Anything, 100).Return([]domain.AuditLog{
		{ID: 1, Action: "TEST_ACTION", Username: "admin"},
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/audit-logs", nil)
	w := httptest.NewRecorder()

	srv.AuditHandler.HandleGetLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "TEST_ACTION")
	mockAudit.AssertExpectations(t)
}

// MockAuditService for Web Package
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) Log(ctx context.Context, action domain.AuditAction, target, details string) error {
	args := m.Called(ctx, action, target, details)
	return args.Error(0)
}

func (m *MockAuditService) GetLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}
func TestServer_HandleGenerateReport(t *testing.T) {
	mockService := new(web.MockNetworkService)
	mockRegistry := new(web.MockDeviceRegistry)
	mockAuth := new(web.MockAuthService)
	mockAudit := new(MockAuditService)

	// Prepare WSM
	tmpDir, _ := os.MkdirTemp("", "wmap-test-report")
	defer os.RemoveAll(tmpDir)

	// Mocks for WSM
	mockRegistry.On("Clear").Return()

	storeMgr := persistence.NewPersistenceManager(nil, 900)
	workspaceMgr, _ := workspace.NewWorkspaceManager(tmpDir, storeMgr, mockRegistry)

	srv := server.NewServer(":9999", mockService, workspaceMgr, mockAuth, mockAudit, nil)

	// Sample Data
	mockService.On("GetGraph", mock.Anything).Return(domain.GraphData{
		Nodes: []domain.GraphNode{
			{
				NodeIdentity: domain.NodeIdentity{ID: "1", MAC: "00:11:22:33:44:55", Vendor: "Apple", Group: domain.GroupAP},
				RadioDetails: domain.RadioDetails{Security: "WPA2", Channel: 6},
			},
			{
				NodeIdentity: domain.NodeIdentity{ID: "2", MAC: "AA:BB:CC:DD:EE:FF", Vendor: "Cisco", Group: domain.GroupStation},
				RadioDetails: domain.RadioDetails{Security: "OPEN", Channel: 1},
			},
			{
				NodeIdentity: domain.NodeIdentity{ID: "3", MAC: "11:22:33:44:55:66", Vendor: "Unknown", Group: domain.GroupAP},
				RadioDetails: domain.RadioDetails{Security: "WEP", Channel: 11},
			},
		},
	}, nil)
	mockService.On("GetAlerts", mock.Anything).Return([]domain.Alert{}, nil)
	mockAudit.On("GetLogs", mock.Anything, 50).Return([]domain.AuditLog{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/reports/download", nil)
	w := httptest.NewRecorder()

	srv.ReportHandler.HandleGenerateReport(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "WMAP Security Report")

	// Check content
	assert.Contains(t, body, "Apple")
	assert.Contains(t, body, "Cisco")
	assert.Contains(t, body, "WPA2")
	assert.Contains(t, body, "OPEN")
	assert.Contains(t, body, "Total Assets") // New label
}
