package sniffer

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/geo"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// PacketHandler encapsulates the logic for parsing packets.
type PacketHandler struct {
	Location         geo.Provider
	Debug            bool
	HandshakeManager *HandshakeManager
	PauseCallback    func(time.Duration)
}

// NewPacketHandler creates a new PacketHandler.
func NewPacketHandler(loc geo.Provider, debug bool, hm *HandshakeManager, pauseFunc func(time.Duration)) *PacketHandler {
	return &PacketHandler{
		Location:         loc,
		Debug:            debug,
		HandshakeManager: hm,
		PauseCallback:    pauseFunc,
	}
}

// HandlePacket processes a single packet and returns a Device if relevant info is found.
// It also returns an Alert if a threat is detected.
func (h *PacketHandler) HandlePacket(packet gopacket.Packet) (*domain.Device, *domain.Alert) {
	// Handshake Capture
	if h.HandshakeManager != nil {
		// Aggressive Pause: If we see EAPOL, pause IMMEDIATELY
		if isEAPOLKey(packet) {
			if h.PauseCallback != nil {
				h.PauseCallback(5 * time.Second)
			}
		}

		saved := h.HandshakeManager.ProcessFrame(packet)
		if saved {
			// Trigger Reactive Hopping: Pause to capture more frames
			if h.PauseCallback != nil {
				h.PauseCallback(5 * time.Second)
			}

			// Alert! Handshake Captured
			// We need BSSID from packet to be accurate, but ProcessFrame handles it internally.
			// Let's extract BSSID purely for the alert if possible.
			// Actually, ProcessFrame knows if it saved.
			// Re-extraction for Alert context:
			dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
			bssid := dot11.Address3.String()

			alert := &domain.Alert{
				Type:      "HANDSHAKE_CAPTURED",
				Subtype:   "WPA_HANDSHAKE",
				DeviceMAC: dot11.Address2.String(), // Source (likely Station or AP)
				TargetMAC: dot11.Address1.String(), // Dest
				Timestamp: time.Now(),
				Message:   "WPA Handshake Captured",
				Details:   fmt.Sprintf("BSSID: %s", bssid),
			}
			return nil, alert
		}
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, nil
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil, nil
	}

	// Active Thread Detection (Deauth/Disassoc)
	// Type: Mgmt (0), Subtype: Disassoc (10) or Deauth (12)
	// Flags checked via gopacket layers if possible, or manual check on Type/Subtype
	if dot11.Type == layers.Dot11TypeMgmtDeauthentication || dot11.Type == layers.Dot11TypeMgmtDisassociation {
		// Create Alert
		// Addr1: Dest (Target), Addr2: Source (Attacker?), Addr3: BSSID
		alert := &domain.Alert{
			Type:      domain.AlertAnomaly,
			Subtype:   "DEAUTH_DETECTED",
			DeviceMAC: dot11.Address2.String(), // Source
			TargetMAC: dot11.Address1.String(), // Dest
			Timestamp: time.Now(),
			Message:   "Deauthentication/Disassociation Frame Detected",
			Details:   "BSSID: " + dot11.Address3.String(),
		}
		if dot11.Address1.String() == "ff:ff:ff:ff:ff:ff" {
			alert.Subtype = "BROADCAST_DEAUTH"
		}
		return nil, alert
	}

	// Basic RF Info
	rssi := -100
	var freq int
	var channelWidth int

	if radiotapLayer := packet.Layer(layers.LayerTypeRadioTap); radiotapLayer != nil {
		if radiotap, ok := radiotapLayer.(*layers.RadioTap); ok {
			rssi = int(radiotap.DBMAntennaSignal)
			freq = int(radiotap.ChannelFrequency)
			// Channel width is better extracted from IEs or specific Radiotap xchannel fields
			// For now, we trust Frequency which is most reliable across cards.
		}
	}

	// Initialize basic Device struct
	device := &domain.Device{
		RSSI:           rssi,
		Frequency:      freq,
		Channel:        frequencyToChannel(freq), // Derive channel from frequency
		ChannelWidth:   channelWidth,
		Latitude:       h.Location.GetLocation().Latitude,
		Longitude:      h.Location.GetLocation().Longitude,
		LastPacketTime: time.Now(),
		LastSeen:       time.Now(),
		// Delay map creation until needed
	}

	// Dispatch based on frame type
	mainType := dot11.Type.MainType()
	if mainType == layers.Dot11TypeMgmt {
		return h.handleMgmtFrame(packet, dot11, device), nil
	} else if mainType == layers.Dot11TypeData {
		return h.handleDataFrame(packet, dot11, device), nil
	}

	return nil, nil
}

func (h *PacketHandler) handleMgmtFrame(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) *domain.Device {
	// Address2 is Source (SA) in Mgmt frames
	device.MAC = dot11.Address2.String()
	device.Vendor = LookupVendor(device.MAC)
	device.PacketsCount = 1
	device.DataTransmitted = int64(len(packet.Data()))

	var ieData []byte
	isBeacon := false
	isProbe := false

	// Check Frame Type based on Dot11 header first (safer than checking for layer existence)
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		isBeacon = true
		device.Type = "ap"
		device.Capabilities = append(device.Capabilities, "Beacon")
		if beacon := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beacon != nil {
			ieData = beacon.LayerPayload()
		}
	} else if dot11.Type == layers.Dot11TypeMgmtProbeReq {
		isProbe = true
		device.Type = "station"
		device.Capabilities = append(device.Capabilities, "Probe")
		if probe := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); probe != nil {
			ieData = probe.LayerPayload()
		}
	} else if dot11.Type == layers.Dot11TypeMgmtProbeResp {
		isBeacon = true // Treat as AP for update purposes (Address2 is Sender/AP)
		device.Type = "ap"
		device.Capabilities = append(device.Capabilities, "ProbeResp")
		if resp := packet.Layer(layers.LayerTypeDot11MgmtProbeResp); resp != nil {
			ieData = resp.LayerPayload()
		}
	} else {
		return nil
	}

	// Fallback: If ieData is empty, check if gopacket decoded IEs into individual layers
	if len(ieData) == 0 {
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeDot11InformationElement {
				if ie, ok := layer.(*layers.Dot11InformationElement); ok {
					// Reconstruct IE bytes: [ID, Length, Value]
					ieData = append(ieData, byte(ie.ID), ie.Length)
					ieData = append(ieData, ie.Info...)
				}
			}
		}
	}

	// Log debug info for interesting packets
	if h.Debug && len(ieData) > 0 {
		log.Printf("DEBUG Handler: MAC=%s Type=%s PayloadLen=%d", device.MAC, device.Type, len(ieData))
	}

	h.parseIEs(ieData, device, h.Debug)

	// Randomized MAC Check & Fingerprinting
	h.analyzeRandomization(dot11.Address2, device)
	h.fingerprintDevice(ieData, device)

	if isProbe && device.SSID != "" {
		if device.ProbedSSIDs == nil {
			device.ProbedSSIDs = make(map[string]time.Time)
		}
		device.ProbedSSIDs[device.SSID] = device.LastPacketTime
	}

	// If it's a beacon, the SSID we found is the one it's broadcasting
	// If it's a probe, the SSID is what it's looking for.
	// The device.SSID field is somewhat dual-purpose here.

	// Check for HasHandshake if it's an AP
	if device.Type == "ap" && h.HandshakeManager != nil {
		device.HasHandshake = h.HandshakeManager.HasHandshake(device.MAC)
	}

	// Only return if we actually classified it
	if isBeacon || isProbe {
		return device
	}
	return nil
}

func (h *PacketHandler) handleDataFrame(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) *domain.Device {
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
		device.Vendor = LookupVendor(device.MAC)
		device.Capabilities = []string{"Data-Tx"}
		device.ConnectedSSID = dot11.Address1.String()
		device.DataTransmitted = payloadLen
		device.PacketsCount = 1
		device.RetryCount = retryVal
		h.analyzeRandomization(dot11.Address2, device)
		return device
	} else if !isToDS && isFromDS {
		// Download: AP -> STA
		// Avoid multicast/broadcast destinations
		if len(dot11.Address1) > 0 && (dot11.Address1[0]&0x01) == 1 {
			return nil
		}

		device.MAC = dot11.Address1.String()
		device.Type = "station" // We track the receiving station
		device.Vendor = LookupVendor(device.MAC)
		device.Capabilities = []string{"Data-Rx"}
		device.ConnectedSSID = dot11.Address2.String()
		device.DataReceived = payloadLen
		device.PacketsCount = 1
		// Retries here are usually AP retrying sending to STA.
		// We might not attribute this to the STA's "bad behavior" but it reflects link quality.
		h.analyzeRandomization(dot11.Address1, device)
		return device
	}

	return nil
}

func (h *PacketHandler) parseIEs(data []byte, device *domain.Device, debug bool) {
	offset := 0
	limit := len(data)

	// Defaults
	device.Security = "OPEN"
	device.Standard = "802.11g/a" // baseline

	// DEBUG
	// fmt.Printf("DEBUG parseIEs: len=%d data=%v\n", len(data), data)

	for offset < limit {
		if offset+1 >= limit {
			break
		}
		id := int(data[offset])
		length := int(data[offset+1])
		offset += 2

		if offset+length > limit {
			break
		}
		val := data[offset : offset+length]

		device.IETags = append(device.IETags, id)

		switch id {
		case 0: // SSID
			valStr := string(val)
			// Check for Hidden SSID (Empty or Null bytes)
			isHidden := len(val) == 0 || val[0] == 0x00

			if isHidden {
				device.SSID = "<HIDDEN>"
			} else {
				device.SSID = valStr
			}
		case 3: // DS Parameter Set (Channel)
			if len(val) > 0 {
				device.Channel = int(val[0])
			}
		case 48: // RSN (WPA2)
			device.Security = "WPA2"
		case 54: // Mobility Domain (802.11r)
			device.Has11r = true
			device.Capabilities = append(device.Capabilities, "11r")
		case 70: // Radio Measurement (802.11k)
			device.Has11k = true
			device.Capabilities = append(device.Capabilities, "11k")
		case 45: // HT Capabilities (802.11n)
			device.Standard = "802.11n (WiFi 4)"
		case 191: // VHT Capabilities (802.11ac)
			device.Standard = "802.11ac (WiFi 5)"
		case 255: // Extension Tag (HE/EHT/etc)
			if len(val) >= 1 {
				extID := int(val[0])
				switch extID {
				case 35: // HE Capabilities (802.11ax)
					device.Standard = "802.11ax (WiFi 6)"
					device.IsWiFi6 = true
				case 108: // EHT Capabilities (802.11be)
					device.Standard = "802.11be (WiFi 7)"
					device.IsWiFi7 = true
					device.IsWiFi6 = true
				}
			}
		case 127: // Extended Capabilities (often contains 802.11v)
			// Check bit 19 for BSS Transition Management
			if len(val) >= 3 {
				if (val[2] & 0x08) != 0 {
					device.Has11v = true
					device.Capabilities = append(device.Capabilities, "11v")
				}
			}
		case 221: // Vendor Specific
			// Microsoft WPS check
			if len(val) >= 4 && val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xF2 && val[3] == 0x04 {
				if model := parseWPSAttributes(val[4:], device); model != "" {
					device.Model = model
					if debug {
						// log.Printf("DEBUG: Found WPS Model '%s' for %s", model, device.MAC)
					}
				}
			}
		}

		offset += length
	}

	// Compute Signature if we have tags
	if len(device.IETags) > 0 {
		device.Signature = computeSignature(device.IETags, nil)
	}
}

// parseWPSAttributes extracts Model/Manufacturer/State from WPS IEs
// Returns "Manufacturer Model" string
func parseWPSAttributes(data []byte, device *domain.Device) string {
	model := ""
	manufacturer := ""
	deviceName := ""
	wpsState := ""

	offset := 0
	limit := len(data)

	for offset < limit {
		if offset+4 > limit {
			break
		}
		attrType := (int(data[offset]) << 8) | int(data[offset+1])
		attrLen := (int(data[offset+2]) << 8) | int(data[offset+3])
		offset += 4

		if offset+attrLen > limit {
			break
		}

		valBytes := data[offset : offset+attrLen]
		val := string(valBytes)

		switch attrType {
		case 0x1021: // Manufacturer
			manufacturer = val
		case 0x1023: // Model Name
			model = val
		case 0x1011: // Device Name
			deviceName = val
		case 0x1044: // WPS State
			if len(valBytes) > 0 {
				switch valBytes[0] {
				case 0x01:
					wpsState = "Unconfigured"
				case 0x02:
					wpsState = "Configured"
				}
			}
		}

		offset += attrLen
	}

	if wpsState != "" {
		device.WPSInfo = wpsState
	}

	// Fallback to DeviceName if Model is empty
	if model == "" && deviceName != "" {
		model = deviceName
	}

	if model != "" {
		if manufacturer != "" {
			return manufacturer + " " + model
		}
		return model
	}
	return ""
}

// analyzeRandomization checks for Locally Administered Address
func (h *PacketHandler) analyzeRandomization(mac net.HardwareAddr, device *domain.Device) {
	if len(mac) > 0 && (mac[0]&0x02) != 0 {
		device.IsRandomized = true
		device.Vendor = "Randomized"
		// Future: Use Signature to guess vendor even if randomized
	}
}

// fingerprintDevice attempts to identify OS based on IE patterns
func (h *PacketHandler) fingerprintDevice(data []byte, device *domain.Device) {
	// Simple heuristic: specific vendor IEs
	// Apple Vendor OUI: 00:17:F2
	// Microsoft Vendor OUI: 00:50:F2

	hasApple := false
	hasMSFT := false
	offset := 0
	limit := len(data)

	for offset < limit {
		if offset+1 >= limit {
			break
		}
		id := int(data[offset])
		length := int(data[offset+1])
		offset += 2
		if offset+length > limit {
			break
		}
		val := data[offset : offset+length]

		if id == 221 && length >= 3 {
			if val[0] == 0x00 && val[1] == 0x17 && val[2] == 0xF2 {
				hasApple = true
			}
			if val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xF2 {
				hasMSFT = true
			}
		}
		offset += length
	}

	if hasApple {
		device.OS = "iOS/macOS"
		if device.IsRandomized {
			device.Vendor = "Apple (Randomized)"
		}
	} else if hasMSFT {
		device.OS = "Windows"
	}
}

// frequencyToChannel converts WiFi frequency (MHz) to channel number
func frequencyToChannel(freq int) int {
	// 2.4 GHz band (channels 1-14)
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq - 2407) / 5
	}

	// 5 GHz band (channels 36-165)
	if freq >= 5170 && freq <= 5825 {
		return (freq - 5000) / 5
	}

	// 6 GHz band - WiFi 6E (channels 1-233)
	if freq >= 5955 && freq <= 7115 {
		return (freq - 5950) / 5
	}

	return 0
}

func isEAPOLKey(packet gopacket.Packet) bool {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		if eapol, ok := eapolLayer.(*layers.EAPOL); ok {
			return eapol.Type == layers.EAPOLTypeKey
		}
	}
	return false
}
