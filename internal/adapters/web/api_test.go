package handlers

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

func TestScanHandler_HandleScan(t *testing.T) {
	mockSvc := &mockNetworkService{}
	handler := NewAPI(mockSvc, mockSvc)

	t.Run("Valid Request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
		w := httptest.NewRecorder()

		mockSvc.On("TriggerScan", mock.Anything).Return(nil).Once()

		handler.HandleScan(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "scan_initiated")
	})
}

func TestScanHandler_HandleChannels(t *testing.T) {
	mockSvc := &mockNetworkService{}
	handler := NewAPI(mockSvc, mockSvc)

	t.Run("GET Channels - Global", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/channels", nil)
		w := httptest.NewRecorder()

		mockSvc.On("GetChannels", mock.Anything).Return([]int{1, 6, 11}, nil).Once()

		handler.HandleGetChannels(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Len(t, resp["channels"], 3)
	})

	t.Run("POST Channels - Interface", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"interface": "wlan0",
			"channels":  []int{1, 3, 5},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/channels", bytes.NewReader(body))
		w := httptest.NewRecorder()

		mockSvc.On("SetInterfaceChannels", mock.Anything, "wlan0", []int{1, 3, 5}).Return(nil).Once()

		handler.HandleUpdateChannels(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestScanHandler_HandleListInterfaces(t *testing.T) {
	mockSvc := &mockNetworkService{}
	handler := NewAPI(mockSvc, mockSvc)

	t.Run("Valid Request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/interfaces", nil)
		w := httptest.NewRecorder()

		details := []domain.InterfaceInfo{{Name: "wlan0", MAC: "AA:BB:CC:DD:EE:FF"}}
		mockSvc.On("GetInterfaceDetails", mock.Anything).Return(details, nil).Once()

		handler.HandleListInterfaces(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Len(t, resp["interfaces"], 1)
	})
}
