package export

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// ExportJSON writes devices as a JSON array.
// Note: For very large datasets, use StreamExportJSON.
func ExportJSON(w io.Writer, devices []domain.Device) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(devices)
}

// StreamExportJSON writes devices from a channel as a JSON array to avoid loading everything in memory.
func StreamExportJSON(w io.Writer, devices <-chan domain.Device) error {
	if _, err := io.WriteString(w, "[\n"); err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("  ", "  ")
	first := true

	for d := range devices {
		if !first {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
		}
		if err := encoder.Encode(d); err != nil {
			return err
		}
		first = false
	}

	_, err := io.WriteString(w, "\n]")
	return err
}

// ExportCSV writes devices as CSV with headers.
// Optimized to reuse memory and use faster string conversions.
func ExportCSV(w io.Writer, devices []domain.Device) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header row
	headers := []string{
		"MAC", "Type", "Vendor", "VendorConfidence", "SSID", "Security", "Crypto", "Standard",
		"RSSI", "Channel", "Frequency", "ChannelWidth",
		"Model", "OS", "WPSInfo",
		"DataTx", "DataRx", "Packets", "Retries",
		"IsRandomized", "IsWiFi6", "IsWiFi7",
		"FirstSeen", "LastSeen",
		"Has11k", "Has11v", "Has11r",
		"HasHandshake", "HandshakeFile",
		"Signature", "Capabilities",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Data rows - Pre-allocate a single row slice to reduce GC pressure
	row := make([]string, len(headers))
	for i := range devices {
		d := &devices[i]
		prepareDeviceRow(row, d)
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

// StreamExportCSV writes devices from a channel as CSV to avoid loading everything in memory.
func StreamExportCSV(w io.Writer, devices <-chan domain.Device) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	headers := []string{
		"MAC", "Type", "Vendor", "VendorConfidence", "SSID", "Security", "Crypto", "Standard",
		"RSSI", "Channel", "Frequency", "ChannelWidth",
		"Model", "OS", "WPSInfo",
		"DataTx", "DataRx", "Packets", "Retries",
		"IsRandomized", "IsWiFi6", "IsWiFi7",
		"FirstSeen", "LastSeen",
		"Has11k", "Has11v", "Has11r",
		"HasHandshake", "HandshakeFile",
		"Signature", "Capabilities",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	row := make([]string, len(headers))
	for d := range devices {
		prepareDeviceRow(row, &d)
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

func prepareDeviceRow(row []string, d *domain.Device) {
	row[0] = d.MAC
	row[1] = string(d.Type)
	row[2] = d.Vendor
	row[3] = strconv.FormatFloat(float64(d.VendorConfidence), 'f', 2, 32)
	row[4] = d.SSID
	row[5] = d.Security
	row[6] = d.Crypto
	row[7] = d.Standard
	row[8] = strconv.Itoa(d.RSSI)
	row[9] = strconv.Itoa(d.Channel)
	row[10] = strconv.Itoa(d.Frequency)
	row[11] = strconv.Itoa(d.ChannelWidth)
	row[12] = d.Model
	row[13] = d.OS
	row[14] = d.WPSInfo
	row[15] = strconv.FormatInt(d.DataTransmitted, 10)
	row[16] = strconv.FormatInt(d.DataReceived, 10)
	row[17] = strconv.Itoa(d.PacketsCount)
	row[18] = strconv.Itoa(d.RetryCount)
	row[19] = strconv.FormatBool(d.IsRandomized)
	row[20] = strconv.FormatBool(d.IsWiFi6)
	row[21] = strconv.FormatBool(d.IsWiFi7)
	row[22] = d.FirstSeen.Format(time.RFC3339)
	row[23] = d.LastSeen.Format(time.RFC3339)
	row[24] = strconv.FormatBool(d.Has11k)
	row[25] = strconv.FormatBool(d.Has11v)
	row[26] = strconv.FormatBool(d.Has11r)
	row[27] = strconv.FormatBool(d.HasHandshake)
	row[28] = d.HandshakeFile
	row[29] = d.Signature
	row[30] = ""
	if len(d.Capabilities) > 0 {
		for i, cap := range d.Capabilities {
			if i == 0 {
				row[30] = cap
			} else {
				row[30] += "|" + cap
			}
		}
	}
}

// ExportAlertsJSON writes alerts as JSON array.
func ExportAlertsJSON(w io.Writer, alerts []domain.Alert) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(alerts)
}

// StreamExportAlertsJSON writes alerts from a channel as a JSON array.
func StreamExportAlertsJSON(w io.Writer, alerts <-chan domain.Alert) error {
	if _, err := io.WriteString(w, "[\n"); err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("  ", "  ")
	first := true

	for a := range alerts {
		if !first {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
		}
		if err := encoder.Encode(a); err != nil {
			return err
		}
		first = false
	}

	_, err := io.WriteString(w, "\n]")
	return err
}

// ExportAlertsCSV writes alerts as CSV.
func ExportAlertsCSV(w io.Writer, alerts []domain.Alert) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header
	headers := []string{"ID", "Type", "Subtype", "DeviceMAC", "TargetMAC", "Timestamp", "Message", "Details"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Data
	row := make([]string, len(headers))
	for i := range alerts {
		prepareAlertRow(row, &alerts[i])
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

// StreamExportAlertsCSV writes alerts from a channel as CSV.
func StreamExportAlertsCSV(w io.Writer, alerts <-chan domain.Alert) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	headers := []string{"ID", "Type", "Subtype", "DeviceMAC", "TargetMAC", "Timestamp", "Message", "Details"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	row := make([]string, len(headers))
	for a := range alerts {
		prepareAlertRow(row, &a)
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

func prepareAlertRow(row []string, a *domain.Alert) {
	row[0] = a.ID
	row[1] = string(a.Type)
	row[2] = a.Subtype
	row[3] = a.DeviceMAC
	row[4] = a.TargetMAC
	row[5] = a.Timestamp.Format(time.RFC3339)
	row[6] = a.Message
	row[7] = a.Details
}
