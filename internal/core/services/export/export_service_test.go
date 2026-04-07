package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestExportJSON(t *testing.T) {
	devices := []domain.Device{
		{MAC: "00:11:22:33:44:55", SSID: "TestNet", RSSI: -50},
	}

	var buf bytes.Buffer
	err := ExportJSON(&buf, devices)
	assert.NoError(t, err)

	var decoded []domain.Device
	err = json.Unmarshal(buf.Bytes(), &decoded)
	assert.NoError(t, err)
	assert.Len(t, decoded, 1)
	assert.Equal(t, "00:11:22:33:44:55", decoded[0].MAC)
}

func TestExportCSV(t *testing.T) {
	devices := []domain.Device{
		{
			MAC:       "00:11:22:33:44:55",
			SSID:      "TestNet",
			RSSI:      -50,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
	}

	var buf bytes.Buffer
	err := ExportCSV(&buf, devices)
	assert.NoError(t, err)

	content := buf.String()
	assert.Contains(t, content, "MAC,Type,Vendor,VendorConfidence,SSID,Security,Crypto,Standard")
	assert.Contains(t, content, "00:11:22:33:44:55")
	assert.Contains(t, content, "TestNet")
}

func TestStreamExportJSON(t *testing.T) {
	devicesChan := make(chan domain.Device, 1)
	devicesChan <- domain.Device{MAC: "aa:bb:cc:dd:ee:ff", SSID: "StreamNet"}
	close(devicesChan)

	var buf bytes.Buffer
	err := StreamExportJSON(&buf, devicesChan)
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "aa:bb:cc:dd:ee:ff")
	assert.Contains(t, buf.String(), "StreamNet")
}

func TestStreamExportCSV(t *testing.T) {
	devicesChan := make(chan domain.Device, 1)
	devicesChan <- domain.Device{
		MAC:       "11:22:33:44:55:66",
		SSID:      "StreamCSV",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	close(devicesChan)

	var buf bytes.Buffer
	err := StreamExportCSV(&buf, devicesChan)
	assert.NoError(t, err)

	content := buf.String()
	assert.Contains(t, content, "11:22:33:44:55:66")
	assert.Contains(t, content, "StreamCSV")
}

func TestExportAlertsJSON(t *testing.T) {
	alerts := []domain.Alert{
		{ID: "alert-1", Type: domain.AlertAnomaly, Message: "Deauth detected"},
	}

	var buf bytes.Buffer
	err := ExportAlertsJSON(&buf, alerts)
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "alert-1")
	assert.Contains(t, buf.String(), "Deauth detected")
}

func TestExportAlertsCSV(t *testing.T) {
	alerts := []domain.Alert{
		{
			ID:        "alert-1",
			Type:      domain.AlertAnomaly,
			Message:   "Deauth detected",
			Timestamp: time.Now(),
		},
	}

	var buf bytes.Buffer
	err := ExportAlertsCSV(&buf, alerts)
	assert.NoError(t, err)

	content := buf.String()
	assert.Contains(t, content, "ID,Type,Subtype")
	assert.Contains(t, content, "alert-1")
}

func TestStreamExportAlertsJSON(t *testing.T) {
	alertsChan := make(chan domain.Alert, 1)
	alertsChan <- domain.Alert{ID: "stream-alert-1", Message: "Streaming JSON alert"}
	close(alertsChan)

	var buf bytes.Buffer
	err := StreamExportAlertsJSON(&buf, alertsChan)
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "stream-alert-1")
}

func TestStreamExportAlertsCSV(t *testing.T) {
	alertsChan := make(chan domain.Alert, 1)
	alertsChan <- domain.Alert{
		ID:        "stream-alert-csv",
		Timestamp: time.Now(),
	}
	close(alertsChan)

	var buf bytes.Buffer
	err := StreamExportAlertsCSV(&buf, alertsChan)
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "stream-alert-csv")
}
