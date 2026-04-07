package domain

import (
	"errors"
	"time"
)

// DeviceType defines the role of a WiFi device.
type DeviceType string

const (
	DeviceTypeAP      DeviceType = "ap"
	DeviceTypeStation DeviceType = "station"
	DeviceTypeUnknown DeviceType = "unknown"
)

// ConnectionState defines the current association status.
type ConnectionState string

const (
	StateDisconnected   ConnectionState = "disconnected"
	StateAuthenticating ConnectionState = "authenticating"
	StateAssociating    ConnectionState = "associating"
	StateHandshake      ConnectionState = "handshake"
	StateConnected      ConnectionState = "connected"
)

// Device represents a WiFi entity (AP or Station) detected in the environment.
// It serves as the primary aggregate root for RF and security data.
type Device struct {
	// --- Identity & Meta ---
	MAC          string     `json:"mac"`
	Type         DeviceType `json:"type"`   // "station", "ap"
	Vendor       string     `json:"vendor"` // Resolved from OUI
	Model        string     `json:"model,omitempty"`
	OS           string     `json:"os,omitempty"`
	IsRandomized bool       `json:"is_randomized"`

	// --- RF & Radio State ---
	RSSI           int       `json:"rssi"`
	Channel        int       `json:"channel,omitempty"`
	Frequency      int       `json:"freq,omitempty"`
	ChannelWidth   int       `json:"bw,omitempty"`
	Standard       string    `json:"standard,omitempty"` // e.g. "802.11ax"
	IsWiFi6        bool      `json:"is_wifi6"`
	IsWiFi7        bool      `json:"is_wifi7"`
	LastPacketTime time.Time `json:"last_packet_time"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`

	// --- Network Protocol & Security ---
	SSID           string          `json:"ssid,omitempty"` // Beacon SSID (AP) or last probed (Sta)
	Capabilities   []string        `json:"capabilities,omitempty"`
	Crypto         string          `json:"crypto,omitempty"`
	Security       string          `json:"security,omitempty"`
	WPSInfo        string          `json:"wps_info,omitempty"`
	RSNInfo        *RSNInfo        `json:"rsn_info,omitempty"`
	WPSDetails     *WPSDetails     `json:"wps_details,omitempty"`
	MobilityDomain *MobilityDomain `json:"mobility_domain,omitempty"`
	BSSLoad        *BSSLoad        `json:"bss_load,omitempty"`

	// Protocol Flags (802.11k/v/r)
	Has11k bool `json:"has11k,omitempty"`
	Has11v bool `json:"has11v,omitempty"`
	Has11r bool `json:"has11r,omitempty"`

	// Handshake Details
	HasHandshake  bool   `json:"has_handshake,omitempty"`
	HandshakeFile string `json:"handshake_file,omitempty"`
	LastANonce    string `json:"last_anonce,omitempty"` // Hex string of last AP Nonce seen

	// Traffic Analytics
	DataTransmitted int64 `json:"data_tx"`
	DataReceived    int64 `json:"data_rx"`
	PacketsCount    int   `json:"packets"`
	RetryCount      int   `json:"retries"`

	// Connectivity & Radio History
	ConnectionState  ConnectionState      `json:"connection_state,omitempty"`
	ConnectionTarget string               `json:"connection_target,omitempty"` // BSSID of the AP
	ConnectionError  string               `json:"connection_error,omitempty"`
	ProbedSSIDs      map[string]time.Time `json:"probed_ssids,omitempty"`
	ConnectedSSID    string               `json:"connected_ssid,omitempty"`
	ObservedSSIDs    []string             `json:"observed_ssids,omitempty"`

	// Advanced Fingerprinting
	IEFingerprint    string  `json:"ie_fingerprint,omitempty"`
	IETags           []int   `json:"ie_tags,omitempty"`
	Signature        string  `json:"signature,omitempty"`
	ProbeHash        string  `json:"probe_hash,omitempty"`
	ManufacturerRaw  string  `json:"manuf_raw,omitempty"`
	VendorConfidence float32 `json:"vendor_confidence,omitempty"`
}

// RSNInfo contains parsed RSN IE details
type RSNInfo struct {
	Version         uint16          `json:"version"`
	GroupCipher     string          `json:"group_cipher"`
	PairwiseCiphers []string        `json:"pairwise_ciphers"`
	AKMSuites       []string        `json:"akm_suites"`
	Capabilities    RSNCapabilities `json:"capabilities"`
	PMKIDs          []string        `json:"pmkids,omitempty"`
	GroupMgmtCipher string          `json:"group_mgmt_cipher,omitempty"`
}

// Clone returns a deep copy of RSNInfo.
func (r *RSNInfo) Clone() *RSNInfo {
	if r == nil {
		return nil
	}
	c := *r
	if r.PairwiseCiphers != nil {
		c.PairwiseCiphers = make([]string, len(r.PairwiseCiphers))
		copy(c.PairwiseCiphers, r.PairwiseCiphers)
	}
	if r.AKMSuites != nil {
		c.AKMSuites = make([]string, len(r.AKMSuites))
		copy(c.AKMSuites, r.AKMSuites)
	}
	if r.PMKIDs != nil {
		c.PMKIDs = make([]string, len(r.PMKIDs))
		copy(c.PMKIDs, r.PMKIDs)
	}
	return &c
}

// RSNCapabilities represents RSN capability bits
type RSNCapabilities struct {
	PreAuth          bool  `json:"pre_auth"`
	NoPairwise       bool  `json:"no_pairwise"`
	PTKSAReplayCount uint8 `json:"ptksa_replay_count"`
	GTKSAReplayCount uint8 `json:"gtksa_replay_count"`
	MFPRequired      bool  `json:"mfp_required"`
	MFPCapable       bool  `json:"mfp_capable"`
	PeerKeyEnabled   bool  `json:"peer_key_enabled"`
	JointMultiBand   bool  `json:"joint_multiband,omitempty"` // Added (Bit 8)
	OCVC             bool  `json:"ocvc,omitempty"`            // Added (Bit 10)
}

// MobilityDomain contains 802.11r FT details
type MobilityDomain struct {
	MDID        uint16 `json:"mdid"`
	OverDS      bool   `json:"over_ds"`
	ResourceReq bool   `json:"resource_req"`
}

// Clone returns a deep copy of MobilityDomain.
func (m *MobilityDomain) Clone() *MobilityDomain {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

// BSSLoad contains details about AP utilization
type BSSLoad struct {
	StationCount       uint16 `json:"station_count"`
	ChannelUtilization uint8  `json:"channel_utilization"` // 0-255 (0-100%)
	AvailableAdmission uint16 `json:"available_admission"`
}

// Clone returns a deep copy of BSSLoad.
func (b *BSSLoad) Clone() *BSSLoad {
	if b == nil {
		return nil
	}
	c := *b
	return &c
}

// WPSDetails contains detailed WPS information
type WPSDetails struct {
	State            string   `json:"state"` // "Configured", "Unconfigured"
	Version          string   `json:"version"`
	Locked           bool     `json:"locked"`
	ConfigMethods    []string `json:"config_methods"`
	DevicePasswordID string   `json:"device_password_id,omitempty"` // Added for PIN/PBC
	Manufacturer     string   `json:"manufacturer"`
	Model            string   `json:"model"`
	DeviceName       string   `json:"device_name"`
}

// Clone returns a deep copy of WPSDetails.
func (w *WPSDetails) Clone() *WPSDetails {
	if w == nil {
		return nil
	}
	c := *w
	if w.ConfigMethods != nil {
		c.ConfigMethods = make([]string, len(w.ConfigMethods))
		copy(c.ConfigMethods, w.ConfigMethods)
	}
	return &c
}

// --- Domain Methods (Encapsulating Logic) ---

// Clone returns a full deep copy of the device.
func (d *Device) Clone() Device {
	c := *d

	// Deep copy slices/maps
	if d.Capabilities != nil {
		c.Capabilities = make([]string, len(d.Capabilities))
		copy(c.Capabilities, d.Capabilities)
	}
	if d.IETags != nil {
		c.IETags = make([]int, len(d.IETags))
		copy(c.IETags, d.IETags)
	}

	// Deep copy pointers
	c.RSNInfo = d.RSNInfo.Clone()
	c.WPSDetails = d.WPSDetails.Clone()
	c.MobilityDomain = d.MobilityDomain.Clone()
	c.BSSLoad = d.BSSLoad.Clone()

	if d.ProbedSSIDs != nil {
		c.ProbedSSIDs = make(map[string]time.Time, len(d.ProbedSSIDs))
		for k, v := range d.ProbedSSIDs {
			c.ProbedSSIDs[k] = v
		}
	}
	if d.ObservedSSIDs != nil {
		c.ObservedSSIDs = make([]string, len(d.ObservedSSIDs))
		copy(c.ObservedSSIDs, d.ObservedSSIDs)
	}

	return c
}

// UpdateFrom merges data from another device observation into this one.
func (d *Device) UpdateFrom(newDevice Device) {
	d.LastPacketTime = newDevice.LastPacketTime
	d.LastSeen = newDevice.LastPacketTime
	d.RSSI = newDevice.RSSI

	if newDevice.Vendor != "" {
		d.Vendor = newDevice.Vendor
	}

	// APs take precedence over stations
	if newDevice.Type != "" {
		if newDevice.Type == DeviceTypeAP || d.Type == "" {
			d.Type = newDevice.Type
		}
	}

	if newDevice.Signature != "" {
		d.Signature = newDevice.Signature
		d.IETags = newDevice.IETags
	}

	if newDevice.Security != "" {
		d.Security = newDevice.Security
	}
	if newDevice.Standard != "" {
		d.Standard = newDevice.Standard
	}
	if newDevice.Model != "" {
		d.Model = newDevice.Model
	}
	if newDevice.Frequency > 0 {
		d.Frequency = newDevice.Frequency
	}
	if newDevice.WPSInfo != "" {
		d.WPSInfo = newDevice.WPSInfo
	}
	if newDevice.HasHandshake {
		d.HasHandshake = true
	}
	if newDevice.MobilityDomain != nil {
		d.MobilityDomain = newDevice.MobilityDomain
	}
	if newDevice.LastANonce != "" {
		d.LastANonce = newDevice.LastANonce
	}

	if newDevice.Channel > 0 {
		d.Channel = newDevice.Channel
	}

	if newDevice.Has11k {
		d.Has11k = true
	}
	if newDevice.Has11v {
		d.Has11v = true
	}
	if newDevice.Has11r {
		d.Has11r = true
	}

	d.DataTransmitted += newDevice.DataTransmitted
	d.DataReceived += newDevice.DataReceived
	d.PacketsCount += newDevice.PacketsCount
	d.RetryCount += newDevice.RetryCount
	if newDevice.ChannelWidth > 0 {
		d.ChannelWidth = newDevice.ChannelWidth
	}

	if d.ProbedSSIDs == nil {
		d.ProbedSSIDs = make(map[string]time.Time)
	}
	for ssid, ts := range newDevice.ProbedSSIDs {
		d.ProbedSSIDs[ssid] = ts
	}

	if len(newDevice.ObservedSSIDs) > 0 {
		if d.ObservedSSIDs == nil {
			d.ObservedSSIDs = make([]string, 0)
		}
		// Merge unique SSIDs
		for _, newSSID := range newDevice.ObservedSSIDs {
			found := false
			for _, existingSSID := range d.ObservedSSIDs {
				if existingSSID == newSSID {
					found = true
					break
				}
			}
			if !found {
				d.ObservedSSIDs = append(d.ObservedSSIDs, newSSID)
			}
		}
	}

	if newDevice.SSID != "" {
		d.SSID = newDevice.SSID
	}
	if newDevice.ConnectedSSID != "" {
		d.ConnectedSSID = newDevice.ConnectedSSID
	}

	if newDevice.ConnectionState != "" {
		d.ConnectionState = newDevice.ConnectionState
		d.ConnectionTarget = newDevice.ConnectionTarget
		d.ConnectionError = newDevice.ConnectionError
	}
}

// IsAP returns true if the device is acting as an Access Point.
func (d *Device) IsAP() bool {
	return d.Type == DeviceTypeAP
}

// IsStation returns true if the device is acting as a client station.
func (d *Device) IsStation() bool {
	return d.Type == DeviceTypeStation
}

// IsBypassingPrivacy check if the device uses randomized MACs or other privacy techniques.
func (d *Device) IsBypassingPrivacy() bool {
	return d.IsRandomized || d.ProbeHash != ""
}

// IsActive returns true if the device has been seen within the provided duration.
func (d *Device) IsActive(timeout time.Duration) bool {
	return time.Since(d.LastSeen) < timeout
}

// UpdateTraffic increments the traffic statistics for the device.
func (d *Device) UpdateTraffic(tx, rx int64, packets int) {
	d.DataTransmitted += tx
	d.DataReceived += rx
	d.PacketsCount += packets
}

// ToGraphNode converts a Device domain object into a GraphNode DTO for visualization.
func (d *Device) ToGraphNode() GraphNode {
	group := GraphGroup(d.Type)
	if group == "" {
		group = GroupStation
	}

	// Format label: MAC + (Vendor) + [Frequency Band]
	label := d.MAC + "\n(" + d.Vendor + ")"
	if d.Frequency > 3000 {
		label += "\n[5GHz]"
	}

	// Map probed SSIDs to list
	probedSSIDs := make([]string, 0, len(d.ProbedSSIDs))
	for ssid := range d.ProbedSSIDs {
		probedSSIDs = append(probedSSIDs, ssid)
	}

	return GraphNode{
		NodeIdentity: NodeIdentity{
			ID:        "dev_" + d.MAC,
			Label:     label,
			Group:     group,
			MAC:       d.MAC,
			Vendor:    d.Vendor,
			Signature: d.Signature,
			Model:     d.Model,
			OS:        d.OS,
			FirstSeen: d.FirstSeen,
			LastSeen:  d.LastSeen,
		},
		RadioDetails: RadioDetails{
			SSID:           d.SSID,
			Security:       d.Security,
			Standard:       d.Standard,
			WPSInfo:        d.WPSInfo,
			HandshakeFile:  d.HandshakeFile,
			Capabilities:   d.Capabilities,
			ProbedSSIDs:    probedSSIDs,
			IETags:         d.IETags,
			RSNInfo:        d.RSNInfo,
			WPSDetails:     d.WPSDetails,
			MobilityDomain: d.MobilityDomain,
			Channel:        d.Channel,
			ChannelWidth:   d.ChannelWidth,
			Frequency:      d.Frequency,
			RSSI:           d.RSSI,
			IsWiFi6:        d.IsWiFi6,
			IsWiFi7:        d.IsWiFi7,
			IsRandomized:   d.IsRandomized,
			HasHandshake:   d.HasHandshake,
		},
		TrafficStats: TrafficStats{
			DataTransmitted: d.DataTransmitted,
			DataReceived:    d.DataReceived,
			PacketsCount:    d.PacketsCount,
			RetryCount:      d.RetryCount,
		},
		ConnectionDetails: ConnectionDetails{
			ConnectionState:  d.ConnectionState,
			ConnectionTarget: d.ConnectionTarget,
			ConnectionError:  d.ConnectionError,
		},
	}
}

// Validate checks if the device data is consistent and valid.
func (d *Device) Validate() error {
	// In a real scenario, we would check MAC format, valid types, etc.
	if d.MAC == "" {
		return errors.New("MAC address is required")
	}
	return nil
}
