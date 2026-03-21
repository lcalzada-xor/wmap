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
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// HandshakeManager defines the interface required by parser to interact with handshakes.
type HandshakeManager interface {
	ProcessFrame(packet gopacket.Packet) bool
	SavePMKID(packet gopacket.Packet, bssid string, station string)
	HasHandshake(mac string) bool
	GetHandshakeFile(mac string) string
}

// PacketHandler encapsulates the logic for parsing packets.
type PacketHandler struct {
	Debug             bool
	HandshakeManager  HandshakeManager
	FingerprintEngine *fingerprint.FingerprintEngine
	VendorRepo        fingerprint.VendorRepository
	PauseCallback     func(time.Duration)

	// Optimization: Throttle cache (Sharded)
	throttleCache *ShardedCache

	// State Management
	StateManager *domain.ConnectionStateManager
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
func NewPacketHandler(debug bool, hm HandshakeManager, repo fingerprint.VendorRepository, pauseFunc func(time.Duration)) *PacketHandler {
	return &PacketHandler{
		Debug:             debug,
		HandshakeManager:  hm,
		FingerprintEngine: fingerprint.NewFingerprintEngine(fingerprint.NewSignatureStore(nil)),
		VendorRepo:        repo,
		PauseCallback:     pauseFunc,
		throttleCache:     newShardedCache(),
		StateManager:      domain.NewConnectionStateManager(),
	}
}

// HandlePacket processes a single packet and returns a Device if relevant info is found.
// It also returns an Alert if a threat is detected, and a ConnectionEvent if state changed.
func (h *PacketHandler) HandlePacket(packet gopacket.Packet) (dev *domain.Device, alt *domain.Alert, evt *domain.ConnectionEvent) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in PacketHandler: %v", r)
			// Return nil to safely ignore this packet
			dev = nil
			alt = nil
			evt = nil
		}
	}()

	// 1. Handshake & Passive Vulnerability Detection
	if stop, alert := h.handleHandshakeCapture(packet); stop || alert != nil {
		return nil, alert, nil
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, nil, nil
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil, nil, nil
	}

	// 2. Throttling
	if h.shouldThrottlePacket(dot11, packet) {
		return nil, nil, nil
	}

	// 3. Basic RF Info
	rssi, freq, channelWidth := extractBasicDeviceInfo(packet)

	// Initialize basic Device struct
	device := &domain.Device{
		RSSI:           rssi,
		Frequency:      freq,
		Channel:        frequencyToChannel(freq), // Derive channel from frequency
		ChannelWidth:   channelWidth,
		LastPacketTime: time.Now(),
		LastSeen:       time.Now(),
	}

	// 4. Threat Detection (Deauth/Disassoc)
	if threatDev, threatAlert, threatEvt := h.detectThreats(dot11, packet, device); threatAlert != nil {
		return threatDev, threatAlert, threatEvt
	}

	// 5. Dispatch based on frame type
	mainType := dot11.Type.MainType()
	if mainType == layers.Dot11TypeMgmt {
		d, e := h.handleMgmtFrame(packet, dot11, device)
		return d, nil, e
	} else if mainType == layers.Dot11TypeData {
		d, e := h.handleDataFrame(packet, dot11, device)
		return d, nil, e
	}

	return nil, nil, nil
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

func (h *PacketHandler) detectThreats(dot11 *layers.Dot11, packet gopacket.Packet, device *domain.Device) (*domain.Device, *domain.Alert, *domain.ConnectionEvent) {
	// Active Thread Detection (Deauth/Disassoc)
	// Type: Mgmt (0), Subtype: Disassoc (10) or Deauth (12)
	if dot11.Type != layers.Dot11TypeMgmtDeauthentication && dot11.Type != layers.Dot11TypeMgmtDisassociation {
		return nil, nil, nil
	}

	// Throttle Alert Generation to prevent UI flooding
	throttleKey := "alert:deauth:" + dot11.Address2.String()
	if h.throttleCache.shouldThrottle(throttleKey, 200*time.Millisecond) {
		return nil, nil, nil
	}

	// Create Alert
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
	isAPKicking := dot11.Address2.String() == dot11.Address3.String()

	targetMAC := ""
	if isAPKicking {
		targetMAC = dot11.Address1.String()
		if targetMAC == "ff:ff:ff:ff:ff:ff" {
			return nil, alert, nil // Alert is still valid, return event nil? Or maybe event helps context? Let's return nil event for broadcast deauth.
		}
	} else {
		targetMAC = dot11.Address2.String()
	}

	// Extract Reason Code First
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

	// Update State via Manager
	eventType := domain.EventDeauth
	if dot11.Type == layers.Dot11TypeMgmtDisassociation {
		eventType = domain.EventDisassoc
	}

	event := domain.ConnectionEvent{
		Type:      eventType,
		SourceMAC: dot11.Address2.String(),
		TargetMAC: dot11.Address1.String(),
		Timestamp: time.Now(),
		Reason:    int(reasonCode),
	}

	newState, newTarget := h.StateManager.UpdateState(targetMAC, event)

	// Update Device State for the Station
	device.MAC = targetMAC
	device.ConnectionState = newState
	device.ConnectionTarget = newTarget
	device.ConnectedSSID = "" // Clear connected SSID on deauth
	device.Vendor = h.getVendor(device.MAC)

	if foundReason {
		alert.Details += fmt.Sprintf(", Reason: %d", reasonCode)
		if reasonCode == 2 || reasonCode == 15 || reasonCode == 23 {
			device.ConnectionError = "auth_failed"
		}
	}

	return device, alert, &event
}

func (h *PacketHandler) handleMgmtFrame(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	device.MAC = dot11.Address2.String()
	device.Vendor = h.getVendor(device.MAC)
	device.PacketsCount = 1
	device.DataTransmitted = int64(len(packet.Data()))

	var ieData []byte
	isBeacon := false
	isProbe := false

	switch dot11.Type {
	case layers.Dot11TypeMgmtBeacon:
		h.handleBeacon(packet, device, &ieData)
		isBeacon = true
	case layers.Dot11TypeMgmtProbeReq:
		h.handleProbeReq(packet, device, &ieData)
		isProbe = true
	case layers.Dot11TypeMgmtProbeResp:
		h.handleProbeResp(packet, device, &ieData)
		isBeacon = true
	case layers.Dot11TypeMgmtAssociationReq, layers.Dot11TypeMgmtReassociationReq:
		return h.handleAssocReq(dot11, device)
	case layers.Dot11TypeMgmtAuthentication:
		return h.handleAuth(packet, dot11, device)
	case layers.Dot11TypeMgmtAction:
		h.handleAction(packet, dot11, device, &ieData)
	case layers.Dot11TypeMgmtDeauthentication, layers.Dot11TypeMgmtDisassociation:
		return h.handleDeauth(dot11, device)
	default:
		return nil, nil
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
		if device.HasHandshake {
			device.HandshakeFile = h.HandshakeManager.GetHandshakeFile(device.MAC)
		}
	}

	// Only return if we actually classified it
	if isBeacon || isProbe || device.ConnectionState == domain.StateAssociating || device.ConnectionState == domain.StateAuthenticating || device.ConnectionState == domain.StateDisconnected || device.ConnectionState == domain.StateConnected || device.ConnectionState == domain.StateHandshake {
		return device, nil // Return device but nil event if logic above didn't return early
	}
	return nil, nil
}

func (h *PacketHandler) handleBeacon(packet gopacket.Packet, device *domain.Device, ieData *[]byte) {
	device.Type = "ap"
	device.Capabilities = append(device.Capabilities, "Beacon")
	if layer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); layer != nil {
		if beacon, ok := layer.(*layers.Dot11MgmtBeacon); ok {
			*ieData = beacon.LayerPayload()
		} else {
			*ieData = layer.LayerPayload()
		}
	}
}

func (h *PacketHandler) handleProbeReq(packet gopacket.Packet, device *domain.Device, ieData *[]byte) {
	device.Type = "station"
	device.Capabilities = append(device.Capabilities, "Probe")
	if layer := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); layer != nil {
		if probe, ok := layer.(*layers.Dot11MgmtProbeReq); ok {
			*ieData = probe.LayerPayload()
		} else {
			*ieData = layer.LayerPayload()
		}
	}
}

func (h *PacketHandler) handleProbeResp(packet gopacket.Packet, device *domain.Device, ieData *[]byte) {
	device.Type = "ap"
	device.Capabilities = append(device.Capabilities, "ProbeResp")
	if layer := packet.Layer(layers.LayerTypeDot11MgmtProbeResp); layer != nil {
		if resp, ok := layer.(*layers.Dot11MgmtProbeResp); ok {
			*ieData = resp.LayerPayload()
		} else {
			*ieData = layer.LayerPayload()
		}
	}
}

func (h *PacketHandler) handleAssocReq(dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	device.Type = "station"
	device.Capabilities = append(device.Capabilities, "AssocReq")

	target := dot11.Address1.String()
	event := domain.ConnectionEvent{
		Type:      domain.EventAssocReq,
		SourceMAC: device.MAC,
		TargetMAC: target,
		Timestamp: time.Now(),
	}
	newState, newTarget := h.StateManager.UpdateState(device.MAC, event)
	device.ConnectionState = newState
	device.ConnectionTarget = newTarget

	return device, &event
}

func (h *PacketHandler) handleAuth(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	device.Type = "station"
	device.Capabilities = append(device.Capabilities, "Auth")

	if authLayer := packet.Layer(layers.LayerTypeDot11MgmtAuthentication); authLayer != nil {
		if auth, ok := authLayer.(*layers.Dot11MgmtAuthentication); ok {
			if auth.Status != 0 {
				device.ConnectionError = fmt.Sprintf("auth_failed_code_%d", auth.Status)
			}
		}
	}

	target := dot11.Address1.String()
	event := domain.ConnectionEvent{
		Type:      domain.EventAuthReq,
		SourceMAC: device.MAC,
		TargetMAC: target,
		Timestamp: time.Now(),
	}
	newState, newTarget := h.StateManager.UpdateState(device.MAC, event)
	device.ConnectionState = newState
	device.ConnectionTarget = newTarget

	return device, &event
}

func (h *PacketHandler) handleAction(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device, ieData *[]byte) {
	device.Type = "station"
	if isAP(dot11) {
		device.Type = "ap"
	}

	if layer := packet.Layer(layers.LayerTypeDot11MgmtAction); layer != nil {
		payload := layer.LayerPayload()
		if len(payload) > 0 {
			category := payload[0]
			switch category {
			case 0:
				device.Capabilities = append(device.Capabilities, "11h")
			case 5:
				device.Has11k = true
				device.Capabilities = append(device.Capabilities, "11k")
			case 6:
				device.Has11r = true
				device.Capabilities = append(device.Capabilities, "11r")
			case 10:
				device.Has11v = true
				device.Capabilities = append(device.Capabilities, "11v")
			}
		}
		*ieData = payload
	}
}

func (h *PacketHandler) handleDeauth(dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	eventType := domain.EventDeauth
	if dot11.Type == layers.Dot11TypeMgmtDisassociation {
		eventType = domain.EventDisassoc
	}

	isAPKicking := dot11.Address2.String() == dot11.Address3.String()
	targetMAC := dot11.Address2.String()
	if isAPKicking {
		targetMAC = dot11.Address1.String()
	}

	event := domain.ConnectionEvent{
		Type:      eventType,
		SourceMAC: dot11.Address2.String(),
		TargetMAC: dot11.Address1.String(),
		Timestamp: time.Now(),
	}
	newState, newTarget := h.StateManager.UpdateState(targetMAC, event)

	if targetMAC == device.MAC {
		device.ConnectionState = newState
		device.ConnectionTarget = newTarget
		device.ConnectedSSID = ""
	}

	return device, &event
}

func (h *PacketHandler) handleDataFrame(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
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

		target := dot11.Address1.String()
		device.ConnectedSSID = target // Preserving existing behavior (BSSID)

		eventType := domain.EventDataTransfer
		if isEAPOLKey(packet) {
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
		h.FingerprintEngine.AnalyzeRandomization(dot11.Address2, device)
		return device, &event
	} else if !isToDS && isFromDS {
		// Download: AP -> STA
		// Avoid multicast/broadcast destinations
		if len(dot11.Address1) > 0 && (dot11.Address1[0]&0x01) == 1 {
			return nil, nil
		}

		device.MAC = dot11.Address1.String()
		device.Type = "station" // We track the receiving station
		device.Vendor = h.getVendor(device.MAC)
		device.Capabilities = []string{"Data-Rx"}

		target := dot11.Address2.String()
		device.ConnectedSSID = target

		eventType := domain.EventDataTransfer
		if isEAPOLKey(packet) {
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
		// Retries here are usually AP retrying sending to STA.
		h.FingerprintEngine.AnalyzeRandomization(dot11.Address1, device)
		return device, &event
	}

	return nil, nil
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
