package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestServer_HandleAuthFlood(t *testing.T) {
	server, mockService, _, _ := setupServer(t)

	// 1. Valid Start Request
	mockService.On("StartAuthFloodAttack", mock.MatchedBy(func(cfg domain.AuthFloodAttackConfig) bool {
		return cfg.TargetBSSID == "AA:BB:CC:DD:EE:FF" && cfg.PacketCount == 100
	})).Return("auth-123", nil)

	payload := map[string]interface{}{
		"target_bssid":       "AA:BB:CC:DD:EE:FF",
		"packet_count":       100,
		"packet_interval_ms": 10,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/attack/auth-flood/start", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Direct handler call (bypassing router middleware for unit test simplicity,
	// or we can use router if exported. handleAuthFloodStart is private method of Server)
	// We need to call router or make handler public. Server methods are public (Handle...) but lowercase here.
	// Actually s.handleAuthFloodStart is private. But we are in the same package 'web', so we can call it.

	// Note: The new handlers are added in 'auth_flood_handler.go' which is package web.
	// So server.handleAuthFloodStart IS accessible here.

	server.handleAuthFloodStart(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "auth-123")

	// 2. Stop Request
	mockService.On("StopAuthFloodAttack", "auth-123", true).Return(nil)

	reqStop := httptest.NewRequest(http.MethodPost, "/api/attack/auth-flood/stop?id=auth-123&force=true", nil)
	wStop := httptest.NewRecorder()

	server.handleAuthFloodStop(wStop, reqStop)
	assert.Equal(t, http.StatusOK, wStop.Code)

	// 3. Status Request
	mockService.On("GetAuthFloodStatus", "auth-123").Return(domain.AuthFloodAttackStatus{
		ID:          "auth-123",
		Status:      domain.AttackRunning,
		PacketsSent: 50,
	}, nil)

	reqStatus := httptest.NewRequest(http.MethodGet, "/api/attack/auth-flood/status?id=auth-123", nil)
	wStatus := httptest.NewRecorder()

	server.handleAuthFloodStatus(wStatus, reqStatus)
	assert.Equal(t, http.StatusOK, wStatus.Code)
	assert.Contains(t, wStatus.Body.String(), "running")
	assert.Contains(t, wStatus.Body.String(), "50")
}
