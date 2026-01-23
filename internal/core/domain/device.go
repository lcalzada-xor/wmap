package domain

import (
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

	// --- Traffic Analytics ---
	DataTransmitted int64 `json:"data_tx"`
	DataReceived    int64 `json:"data_rx"`
	PacketsCount    int   `json:"packets"`
	RetryCount      int   `json:"retries"`

	// --- Geospatial ---
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lng"`

	// --- Connectivity & Behavioral ---
	ConnectionState  ConnectionState      `json:"connection_state,omitempty"`
	ConnectionTarget string               `json:"connection_target,omitempty"` // BSSID of the AP
	ConnectionError  string               `json:"connection_error,omitempty"`
	HasHandshake     bool                 `json:"has_handshake,omitempty"`
	ProbedSSIDs      map[string]time.Time `json:"probed_ssids,omitempty"`
	ConnectedSSID    string               `json:"connected_ssid,omitempty"`

	ObservedSSIDs []string `json:"observed_ssids,omitempty"`
	// Protocol Flags (802.11k/v/r)
	Has11k bool `json:"has11k,omitempty"`
	Has11v bool `json:"has11v,omitempty"`
	Has11r bool `json:"has11r,omitempty"`

	// Handshake Details
	LastANonce string `json:"last_anonce,omitempty"` // Hex string of last AP Nonce seen

	// --- Advanced Fingerprinting ---
	IEFingerprint    string  `json:"ie_fingerprint,omitempty"`
	IETags           []int   `json:"ie_tags,omitempty"`
	Signature        string  `json:"signature,omitempty"`
	ProbeHash        string  `json:"probe_hash,omitempty"`
	ManufacturerRaw  string  `json:"manuf_raw,omitempty"`
	VendorConfidence float32 `json:"vendor_confidence,omitempty"`

	// --- Domain Relations ---
	Behavioral      *BehavioralProfile `json:"behavioral,omitempty"`
	Vulnerabilities []VulnerabilityTag `json:"vulnerabilities,omitempty"`
}

// RSNInfo contains parsed RSN IE details
type RSNInfo struct {
	Version         uint16          `json:"version"`
	GroupCipher     string          `json:"group_cipher"`
	PairwiseCiphers []string        `json:"pairwise_ciphers"`
	AKMSuites       []string        `json:"akm_suites"`
	Capabilities    RSNCapabilities `json:"capabilities"`
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
}

// MobilityDomain contains 802.11r FT details
type MobilityDomain struct {
	MDID        uint16 `json:"mdid"`
	OverDS      bool   `json:"over_ds"`
	ResourceReq bool   `json:"resource_req"`
}

// WPSDetails contains detailed WPS information
type WPSDetails struct {
	State         string   `json:"state"` // "Configured", "Unconfigured"
	Version       string   `json:"version"`
	Locked        bool     `json:"locked"`
	ConfigMethods []string `json:"config_methods"`
	Manufacturer  string   `json:"manufacturer"`
	Model         string   `json:"model"`
	DeviceName    string   `json:"device_name"`
}

// --- Domain Methods (Encapsulating Logic) ---

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

// HasVulnerability checks if a specific vulnerability has been detected.
func (d *Device) HasVulnerability(name string) bool {
	for _, v := range d.Vulnerabilities {
		if v.Name == name {
			return true
		}
	}
	return false
}
