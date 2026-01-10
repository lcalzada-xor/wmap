package domain

import "time"

// Device represents a WiFi device/entity detected.
type Device struct {
	MAC          string   `json:"mac"`
	Type         string   `json:"type"`   // "station", "ap"
	Vendor       string   `json:"vendor"` // Resolved from OUI
	RSSI         int      `json:"rssi"`
	SSID         string   `json:"ssid,omitempty"` // For APs: Beacon SSID. For Stas: Probed SSID.
	Channel      int      `json:"channel,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"` // e.g. "HT", "VHT", "WPS"
	Crypto       string   `json:"crypto,omitempty"`       // e.g. "WPA2", "OPEN"
	Security     string   `json:"security,omitempty"`     // e.g. "WPA3", "WPA2", "WEP", "OPEN"
	Standard     string   `json:"standard,omitempty"`     // e.g. "802.11ax"
	Model        string   `json:"model,omitempty"`        // e.g. "Sonos One"
	OS           string   `json:"os,omitempty"`           // e.g. "iOS", "Android"
	Frequency    int      `json:"freq,omitempty"`         // e.g. 2412, 5180

	// Traffic & RF Analytics
	DataTransmitted int64 `json:"data_tx"`
	DataReceived    int64 `json:"data_rx"`
	PacketsCount    int   `json:"packets"`
	RetryCount      int   `json:"retries"`
	ChannelWidth    int   `json:"bw,omitempty"` // e.g. 20, 40, 80

	Latitude       float64              `json:"lat"`
	Longitude      float64              `json:"lng"`
	LastPacketTime time.Time            `json:"last_packet_time"`
	FirstSeen      time.Time            `json:"first_seen"`
	LastSeen       time.Time            `json:"last_seen"`
	ProbedSSIDs    map[string]time.Time `json:"probed_ssids,omitempty"`
	ConnectedSSID  string               `json:"connected_ssid,omitempty"`
	IsRandomized   bool                 `json:"is_randomized"`
	IsWiFi6        bool                 `json:"is_wifi6"` // 802.11ax
	IsWiFi7        bool                 `json:"is_wifi7"` // 802.11be
	IETags         []int                `json:"ie_tags,omitempty"`
	Signature      string               `json:"signature,omitempty"` // IE Hash for model identification
	WPSInfo        string               `json:"wps_info,omitempty"`  // WPS State/Version

	// Security & Advanced Protocols (Phase C)
	Has11k       bool `json:"has11k,omitempty"` // 802.11k
	Has11v       bool `json:"has11v,omitempty"` // 802.11v
	Has11r       bool `json:"has11r,omitempty"` // 802.11r
	HasHandshake bool `json:"has_handshake,omitempty"`

	// Behavioral Intelligence (Phase A)
	Behavioral *BehavioralProfile `json:"behavioral,omitempty"`

	// Connection State (Logic 2.0)
	ConnectionState  string `json:"connection_state,omitempty"`  // "disconnected", "associating", "handshake", "connected"
	ConnectionTarget string `json:"connection_target,omitempty"` // BSSID of the AP
	ConnectionError  string `json:"connection_error,omitempty"`  // e.g. "auth_failed"
	// Vulnerability Detection (Passive)
	Vulnerabilities []VulnerabilityTag `json:"vulnerabilities,omitempty"`
	RSNInfo         *RSNInfo           `json:"rsn_info,omitempty"`
	WPSDetails      *WPSDetails        `json:"wps_details,omitempty"`
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

// Connection States
const (
	StateDisconnected   = "disconnected"
	StateAuthenticating = "authenticating"
	StateAssociating    = "associating"
	StateHandshake      = "handshake"
	StateConnected      = "connected"
)
