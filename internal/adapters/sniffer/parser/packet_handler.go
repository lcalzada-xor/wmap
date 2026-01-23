package parser

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint/mapper"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/geo"
)

// PacketHandler encapsulates the logic for parsing packets.
type PacketHandler struct {
	Location          geo.Provider
	Debug             bool
	HandshakeManager  *handshake.HandshakeManager
	FingerprintEngine *fingerprint.FingerprintEngine
	VendorRepo        fingerprint.VendorRepository
	PauseCallback     func(time.Duration)

	// Optimization: Throttle cache (Sharded)
	throttleCache *ShardedCache
}

const shardCount = 32

type ShardedCache struct {
	shards [shardCount]shard
}

type shard struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func newShardedCache() *ShardedCache {
	sc := &ShardedCache{}
	for i := 0; i < shardCount; i++ {
		sc.shards[i].items = make(map[string]time.Time)
	}
	return sc
}

func (sc *ShardedCache) getShard(key string) *shard {
	// Simple hash
	h := 0
	for i := 0; i < len(key); i++ {
		h = 31*h + int(key[i])
	}
	// positive index
	if h < 0 {
		h = -h
	}
	return &sc.shards[h%shardCount]
}

func (sc *ShardedCache) shouldThrottle(key string, duration time.Duration) bool {
	shard := sc.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if lastSeen, exists := shard.items[key]; exists {
		if time.Since(lastSeen) < duration {
			return true
		}
	}
	shard.items[key] = time.Now()
	return false
}

// getVendor returns cached vendor or looks it up
func (h *PacketHandler) getVendor(macStr string) string {
	mac, err := fingerprint.ParseMAC(macStr)
	if err != nil {
		return ""
	}

	// Use context.Background as this is a synchronous lookup in the packet path
	// Ideally we'd propagate context from the top, but packet handling loop is long-running
	if h.VendorRepo == nil {
		return ""
	}
	vendor, err := h.VendorRepo.LookupVendor(context.Background(), mac)
	if err != nil {
		return ""
	}
	return vendor
}

// NewPacketHandler creates a new PacketHandler.
func NewPacketHandler(loc geo.Provider, debug bool, hm *handshake.HandshakeManager, repo fingerprint.VendorRepository, pauseFunc func(time.Duration)) *PacketHandler {
	return &PacketHandler{
		Location:          loc,
		Debug:             debug,
		HandshakeManager:  hm,
		FingerprintEngine: fingerprint.NewFingerprintEngine(fingerprint.NewSignatureStore(nil)),
		VendorRepo:        repo,
		PauseCallback:     pauseFunc,
		throttleCache:     newShardedCache(),
	}
}

// HandlePacket processes a single packet and returns a Device if relevant info is found.
// It also returns an Alert if a threat is detected.
func (h *PacketHandler) HandlePacket(packet gopacket.Packet) (dev *domain.Device, alt *domain.Alert) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in PacketHandler: %v", r)
			// Return nil to safely ignore this packet
			dev = nil
			alt = nil
		}
	}()

	// 1. Handshake & Passive Vulnerability Detection
	if stop, alert := h.handleHandshakeCapture(packet); stop || alert != nil {
		return nil, alert
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, nil
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil, nil
	}

	// 2. Throttling
	if h.shouldThrottlePacket(dot11, packet) {
		return nil, nil
	}

	// 3. Basic RF Info
	rssi, freq, channelWidth := extractBasicDeviceInfo(packet)

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
	}

	// 4. Threat Detection (Deauth/Disassoc)
	if threatDev, threatAlert := h.detectThreats(dot11, packet, device); threatAlert != nil {
		return threatDev, threatAlert
	}

	// 5. Dispatch based on frame type
	mainType := dot11.Type.MainType()
	if mainType == layers.Dot11TypeMgmt {
		return h.handleMgmtFrame(packet, dot11, device), nil
	} else if mainType == layers.Dot11TypeData {
		return h.handleDataFrame(packet, dot11, device), nil
	}

	return nil, nil
}

func (h *PacketHandler) shouldThrottlePacket(dot11 *layers.Dot11, packet gopacket.Packet) bool {
	// Optimization: Packet Throttling
	// Skip processing if we saw this device recently (< 500ms)
	// EXCEPT for critical events (Deauth, Association, Handshake, Data frames)
	// Data frames are critical because they contain connection state information
	sourceMAC := dot11.Address2.String()
	isCritical := dot11.Type == layers.Dot11TypeMgmtDeauthentication ||
		dot11.Type == layers.Dot11TypeMgmtDisassociation ||
		dot11.Type == layers.Dot11TypeMgmtAssociationReq ||
		dot11.Type == layers.Dot11TypeMgmtReassociationReq ||
		dot11.Type == layers.Dot11TypeMgmtAuthentication ||
		dot11.Type.MainType() == layers.Dot11TypeData ||
		isEAPOLKey(packet)

	if !isCritical {
		if h.throttleCache.shouldThrottle(sourceMAC, 500*time.Millisecond) {
			return true
		}
	}
	return false
}

func extractBasicDeviceInfo(packet gopacket.Packet) (rssi, freq, channelWidth int) {
	rssi = -100
	if radiotapLayer := packet.Layer(layers.LayerTypeRadioTap); radiotapLayer != nil {
		if radiotap, ok := radiotapLayer.(*layers.RadioTap); ok {
			rssi = int(radiotap.DBMAntennaSignal)
			freq = int(radiotap.ChannelFrequency)
			// Channel width is better extracted from IEs or specific Radiotap xchannel fields
			// For now, we trust Frequency which is most reliable across cards.
		}
	}
	return
}

func (h *PacketHandler) detectThreats(dot11 *layers.Dot11, packet gopacket.Packet, device *domain.Device) (*domain.Device, *domain.Alert) {
	// Active Thread Detection (Deauth/Disassoc)
	// Type: Mgmt (0), Subtype: Disassoc (10) or Deauth (12)
	if dot11.Type != layers.Dot11TypeMgmtDeauthentication && dot11.Type != layers.Dot11TypeMgmtDisassociation {
		return nil, nil
	}

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

	// Logic: Identify who is disconnecting
	// Addr1: Dest, Addr2: Source, Addr3: BSSID
	isAPKicking := dot11.Address2.String() == dot11.Address3.String()

	targetMAC := ""
	if isAPKicking {
		// AP is kicking the Station. Update the Station (Dest).
		targetMAC = dot11.Address1.String()
		// Ignore Broadcast Deauths for specific device updates for now
		if targetMAC == "ff:ff:ff:ff:ff:ff" {
			// Broadcast Deauth: AP is resetting everyone.
			return nil, alert // Alert is still valid
		}
	} else {
		// Station is leaving. Update the Station (Source).
		targetMAC = dot11.Address2.String()
	}

	// Update Device State for the Station
	device.MAC = targetMAC
	device.ConnectionState = domain.StateDisconnected
	device.ConnectionTarget = ""
	device.ConnectedSSID = ""
	device.Vendor = h.getVendor(device.MAC) // Ensure vendor is set

	// Auth Failure Diagnostics
	// Check Reason Code
	var reasonCode layers.Dot11Reason
	foundReason := false

	if dot11.Type == layers.Dot11TypeMgmtDeauthentication {
		if layer := packet.Layer(layers.LayerTypeDot11MgmtDeauthentication); layer != nil {
			if deauth, ok := layer.(*layers.Dot11MgmtDeauthentication); ok {
				reasonCode = deauth.Reason
				foundReason = true
			}
		}
	} else if dot11.Type == layers.Dot11TypeMgmtDisassociation {
		if layer := packet.Layer(layers.LayerTypeDot11MgmtDisassociation); layer != nil {
			if disassoc, ok := layer.(*layers.Dot11MgmtDisassociation); ok {
				reasonCode = disassoc.Reason
				foundReason = true
			}
		}
	}

	if foundReason {
		alert.Details += fmt.Sprintf(", Reason: %d", reasonCode)
		// Reason 2: Previous authentication no longer valid
		// Reason 15: 4-Way Handshake timeout
		// Reason 23: IEEE 802.1X authentication failed
		if reasonCode == 2 || reasonCode == 15 || reasonCode == 23 {
			device.ConnectionError = "auth_failed"
		}
	}

	return device, alert
}

func (h *PacketHandler) handleMgmtFrame(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) *domain.Device {
	// Address2 is Source (SA) in Mgmt frames
	device.MAC = dot11.Address2.String()
	device.Vendor = h.getVendor(device.MAC)
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
	} else if dot11.Type == layers.Dot11TypeMgmtAssociationReq || dot11.Type == layers.Dot11TypeMgmtReassociationReq {
		// Client -> AP (Requesting connection)
		isProbe = false // Not a probe, but similar client behavior
		device.Type = "station"
		device.Capabilities = append(device.Capabilities, "AssocReq")
		// For Assoc Req, Address1 is BSSID (Target AP)
		device.ConnectionTarget = dot11.Address1.String()
		device.ConnectionState = domain.StateAssociating

		// Note: IE parsing happens below in the consolidated section
	} else if dot11.Type == layers.Dot11TypeMgmtAuthentication {
		// Authentication (Pre-Assoc)
		device.Type = "station"
		device.Capabilities = append(device.Capabilities, "Auth")
		device.ConnectionState = domain.StateAuthenticating
		device.ConnectionTarget = dot11.Address1.String() // BSSID

		if auth := packet.Layer(layers.LayerTypeDot11MgmtAuthentication); auth != nil {
			ieData = auth.LayerPayload()
			// Extract Auth Algorithm and Status if available?
			// gopacket might expose them on the layer struct.
			// Dot11MgmtAuthentication fields: Algorithm, Sequence, Status
			if a, ok := auth.(*layers.Dot11MgmtAuthentication); ok {
				if a.Status != 0 {
					// Auth Failure!
					device.ConnectionError = fmt.Sprintf("auth_failed_code_%d", a.Status)
					// Generate Alert?
				}
			}
		}

	} else if dot11.Type == layers.Dot11TypeMgmtAction {
		// Action Frames (Spectrum, QoS, BlockAck, Radio Measurement, etc.)
		// Address1=RA, Address2=TA (Source), Address3=BSSID
		// We care about Source Capabilities (11k, 11v, 11r active use)
		device.Type = "station" // Usually stations send actions, or APs.
		if isAP(dot11) {
			device.Type = "ap"
		}

		// Parse Category Code (first byte of payload)
		payload := packet.Layer(layers.LayerTypeDot11MgmtAction).LayerPayload()
		if len(payload) > 0 {
			category := payload[0]
			switch category {
			case 0: // Spectrum Management (802.11h)
				device.Capabilities = append(device.Capabilities, "11h")
			case 5: // Radio Measurement (802.11k)
				device.Has11k = true
				device.Capabilities = append(device.Capabilities, "11k")
			case 6: // Fast BSS Transition (802.11r)
				device.Has11r = true
				device.Capabilities = append(device.Capabilities, "11r")
			case 10: // WNM (802.11v)
				device.Has11v = true
				device.Capabilities = append(device.Capabilities, "11v")
			}
		}
		ieData = payload // Might contain IEs too? Action frames structure varies.
		// Usually Action frames act as wrappers.

	} else if dot11.Type == layers.Dot11TypeMgmtDeauthentication || dot11.Type == layers.Dot11TypeMgmtDisassociation {
		// Disconnection detected
		// Addr1: Dest, Addr2: Source.
		// If Source is Client, Client is leaving. If Source is AP, AP is kicking Client.
		// We want to update the CLIENT's state.

		// Check if we are tracking the Source (Client leaving)
		// We return the device corresponding to Address2 (Source) usually.
		device.MAC = dot11.Address2.String()
		device.ConnectionState = domain.StateDisconnected
		device.ConnectionTarget = ""
		// We might want to clear ConnectedSSID too, but let's keep it as "last connected" for now, or clear it if strict.
		// Let's clear ConnectedSSID to be consistent with graph.
		device.ConnectedSSID = ""

		// If Dest is the client (AP kicking client), we need to handle that too?
		// For now, handleMgmtFrame sets device.MAC = Address2.
		// If AP kicks Client, Address2 is AP. We are updating the AP's state? No, AP doesn't have "ConnectionState".
		// We need to support updating the Destination if it's a station.
		// This might require returning multiple devices or handling it in HandlePacket.
		// For simplicity V1: Only handle Client-initiated disconnects here, or if we can handle AP-initiated.
		// Let's stick to standard flow: handleMgmtFrame returns *one* device.

		// Case: AP (Addr2) kicks Station (Addr1).
		// We are currently creating a device for Addr2 (AP).
		// We should probably check if Addr2 is AP.
		// Ideally we catch this in HandlePacket high level logic, but let's leave this for now.
		return device

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

	mapper.ParseIEs(ieData, device)

	// Randomized MAC Check & Fingerprinting
	h.FingerprintEngine.AnalyzeRandomization(dot11.Address2, device)
	// Fingerprint OS if not yet done
	if device.OS == "" {
		mapper.DetectOS(ieData, device)
	}

	if isProbe && device.SSID != "" {
		if device.ProbedSSIDs == nil {
			device.ProbedSSIDs = make(map[string]time.Time)
		}
		device.ProbedSSIDs[device.SSID] = device.LastPacketTime
	}

	// Capture AP SSID variations (Advanced Karma Detection)
	if isBeacon && device.SSID != "" && device.Type == "ap" {
		device.ObservedSSIDs = []string{device.SSID}
	}

	// If it's a beacon, the SSID we found is the one it's broadcasting
	// If it's a probe, the SSID is what it's looking for.
	// The device.SSID field is somewhat dual-purpose here.

	// Check for HasHandshake if it's an AP
	if device.Type == "ap" && h.HandshakeManager != nil {
		device.HasHandshake = h.HandshakeManager.HasHandshake(device.MAC)
	}

	// Only return if we actually classified it
	if isBeacon || isProbe || device.ConnectionState == domain.StateAssociating || device.ConnectionState == domain.StateAuthenticating || device.ConnectionState == domain.StateDisconnected || device.ConnectionState == domain.StateConnected || device.ConnectionState == domain.StateHandshake {
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
		device.Vendor = h.getVendor(device.MAC)
		device.Capabilities = []string{"Data-Tx"}
		device.ConnectedSSID = dot11.Address1.String()
		device.ConnectionTarget = dot11.Address1.String()

		if isEAPOLKey(packet) {
			device.ConnectionState = domain.StateHandshake
		} else {
			device.ConnectionState = domain.StateConnected
		}

		device.DataTransmitted = payloadLen
		device.PacketsCount = 1
		device.RetryCount = retryVal
		h.FingerprintEngine.AnalyzeRandomization(dot11.Address2, device)
		return device
	} else if !isToDS && isFromDS {
		// Download: AP -> STA
		// Avoid multicast/broadcast destinations
		if len(dot11.Address1) > 0 && (dot11.Address1[0]&0x01) == 1 {
			return nil
		}

		device.MAC = dot11.Address1.String()
		device.Type = "station" // We track the receiving station
		device.Vendor = h.getVendor(device.MAC)
		device.Capabilities = []string{"Data-Rx"}
		device.ConnectedSSID = dot11.Address2.String()
		device.ConnectionTarget = dot11.Address2.String()

		if isEAPOLKey(packet) {
			device.ConnectionState = domain.StateHandshake
		} else {
			device.ConnectionState = domain.StateConnected
		}

		device.DataReceived = payloadLen
		device.PacketsCount = 1
		// Retries here are usually AP retrying sending to STA.
		// We might not attribute this to the STA's "bad behavior" but it reflects link quality.
		h.FingerprintEngine.AnalyzeRandomization(dot11.Address1, device)
		return device
	}

	return nil
}

// isAP tries to guess if the frame sender is an AP based on addressing or type
func isAP(dot11 *layers.Dot11) bool {
	// Simple heuristic: If FromDS=1, ToDS=0 -> AP.
	// But Mgmt frames have ToDS=0, FromDS=0.
	// We rely on BSSID position?
	// Addr1=DA, Addr2=SA, Addr3=BSSID.
	// If SA == BSSID, it's likely an AP.
	return dot11.Address2.String() == dot11.Address3.String()
}

// parseWPSAttributes extracts Model/Manufacturer/State from WPS IEs
// Returns "Manufacturer Model" string

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
