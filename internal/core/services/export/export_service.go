package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// ExportJSON writes devices as a JSON array
func ExportJSON(w io.Writer, devices []domain.Device) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(devices)
}

// ExportCSV writes devices as CSV with headers
func ExportCSV(w io.Writer, devices []domain.Device) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header row
	headers := []string{
		"MAC", "Type", "Vendor", "SSID", "Security", "Standard",
		"RSSI", "Channel", "Frequency", "ChannelWidth",
		"Model", "OS", "WPSInfo",
		"DataTx", "DataRx", "Packets", "Retries",
		"IsRandomized", "IsWiFi6", "IsWiFi7",
		"FirstSeen", "LastSeen",
		"Latitude", "Longitude",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Data rows
	for _, d := range devices {
		row := []string{
			d.MAC,
			string(d.Type),
			d.Vendor,
			d.SSID,
			d.Security,
			d.Standard,
			fmt.Sprintf("%d", d.RSSI),
			fmt.Sprintf("%d", d.Channel),
			fmt.Sprintf("%d", d.Frequency),
			fmt.Sprintf("%d", d.ChannelWidth),
			d.Model,
			d.OS,
			d.WPSInfo,
			fmt.Sprintf("%d", d.DataTransmitted),
			fmt.Sprintf("%d", d.DataReceived),
			fmt.Sprintf("%d", d.PacketsCount),
			fmt.Sprintf("%d", d.RetryCount),
			fmt.Sprintf("%t", d.IsRandomized),
			fmt.Sprintf("%t", d.IsWiFi6),
			fmt.Sprintf("%t", d.IsWiFi7),
			d.FirstSeen.Format(time.RFC3339),
			d.LastSeen.Format(time.RFC3339),
			fmt.Sprintf("%.6f", d.Latitude),
			fmt.Sprintf("%.6f", d.Longitude),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

// ExportAlertsJSON writes alerts as JSON array
func ExportAlertsJSON(w io.Writer, alerts []domain.Alert) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(alerts)
}

// ExportAlertsCSV writes alerts as CSV
func ExportAlertsCSV(w io.Writer, alerts []domain.Alert) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header
	headers := []string{"ID", "Type", "Subtype", "DeviceMAC", "TargetMAC", "Timestamp", "Message", "Details"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Data
	for _, a := range alerts {
		row := []string{
			a.ID,
			string(a.Type),
			a.Subtype,
			a.DeviceMAC,
			a.TargetMAC,
			a.Timestamp.Format(time.RFC3339),
			a.Message,
			a.Details,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}
