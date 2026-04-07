package handlers

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DataHandler encapsulates the logic to process 802.11 Data frames
type DataHandler struct {
	FingerprintEngine *fingerprint.FingerprintEngine
	StateManager      *domain.ConnectionStateManager
	VendorLookup      func(string) string
}

// Process parses a data frame, separating uplink/downlink traffic, and updates device state
func (h *DataHandler) Process(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device, isEAPOL bool) (*domain.Device, *domain.ConnectionEvent) {
	isToDS := dot11.Flags.ToDS()
	isFromDS := dot11.Flags.FromDS()
	payloadLen := int64(len(packet.Data()))

	retryVal := 0
	if dot11.Flags.Retry() {
		retryVal = 1
	}

	if isToDS && !isFromDS {
		// Upload: STA -> AP
		device.MAC = dot11.Address2.String()
		device.Type = "station"
		if h.VendorLookup != nil {
			device.Vendor = h.VendorLookup(device.MAC)
		}
		device.Capabilities = []string{"Data-Tx"}

		target := dot11.Address1.String()
		device.ConnectedSSID = target // Preserving existing behavior (BSSID)

		eventType := domain.EventDataTransfer
		if isEAPOL {
			eventType = domain.EventEAPOL
		}

		event := domain.ConnectionEvent{
			Type:      eventType,
			SourceMAC: device.MAC,
			TargetMAC: target,
			Timestamp: time.Now(),
		}
		newState, newTarget := h.StateManager.UpdateState(device.MAC, event)
		device.ConnectionState = newState
		device.ConnectionTarget = newTarget

		device.DataTransmitted = payloadLen
		device.PacketsCount = 1
		device.RetryCount = retryVal
		
		if h.FingerprintEngine != nil {
			h.FingerprintEngine.AnalyzeRandomization(dot11.Address2, device)
		}
		return device, &event
	} else if !isToDS && isFromDS {
		// Download: AP -> STA
		// Avoid multicast/broadcast destinations
		if len(dot11.Address1) > 0 && (dot11.Address1[0]&0x01) == 1 {
			return nil, nil
		}

		device.MAC = dot11.Address1.String()
		device.Type = "station" // We track the receiving station
		if h.VendorLookup != nil {
			device.Vendor = h.VendorLookup(device.MAC)
		}
		device.Capabilities = []string{"Data-Rx"}

		target := dot11.Address2.String()
		device.ConnectedSSID = target

		eventType := domain.EventDataTransfer
		if isEAPOL {
			eventType = domain.EventEAPOL
		}

		event := domain.ConnectionEvent{
			Type:      eventType,
			SourceMAC: device.MAC,
			TargetMAC: target,
			Timestamp: time.Now(),
		}
		newState, newTarget := h.StateManager.UpdateState(device.MAC, event)
		device.ConnectionState = newState
		device.ConnectionTarget = newTarget

		device.DataReceived = payloadLen
		device.PacketsCount = 1
		
		if h.FingerprintEngine != nil {
			h.FingerprintEngine.AnalyzeRandomization(dot11.Address1, device)
		}
		return device, &event
	}

	return nil, nil
}
