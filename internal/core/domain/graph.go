package domain

import "time"

// GraphGroup defines the category of a node.
type GraphGroup string

const (
	GroupAP      GraphGroup = "ap"
	GroupStation GraphGroup = "station"
	GroupNetwork GraphGroup = "network"
)

// GraphNode represents a node in the visualization graph.
// Modularized using composition to separate concerns while maintaining the legacy JSON API.
// Anonymous embedding ensures field promotion for both Go code and JSON serialization.
type GraphNode struct {
	NodeIdentity
	RadioDetails
	TrafficStats
	NodeBehavioralData

	// State and Metadata
	Title           string             `json:"title,omitempty"` // Tooltip/Popup content
	IsStale         bool               `json:"is_stale,omitempty"`
	Vulnerabilities []VulnerabilityTag `json:"vulnerabilities,omitempty"`
}

// NodeIdentity encapsulates basic identification and classification.
type NodeIdentity struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Group     GraphGroup `json:"group"` // "ap", "station", "network"
	MAC       string     `json:"mac,omitempty"`
	Vendor    string     `json:"vendor,omitempty"`
	FirstSeen time.Time  `json:"first_seen,omitempty"`
	LastSeen  time.Time  `json:"last_seen,omitempty"`
}

// RadioDetails encapsulates WiFi physical and link layer attributes.
type RadioDetails struct {
	SSID         string   `json:"ssid,omitempty"`
	Channel      int      `json:"channel,omitempty"`
	ChannelWidth int      `json:"bw"`
	Frequency    int      `json:"frequency,omitempty"`
	RSSI         int      `json:"rssi,omitempty"`
	Security     string   `json:"security,omitempty"`
	Standard     string   `json:"standard,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	IsWiFi6      bool     `json:"is_wifi6,omitempty"`
	IsWiFi7      bool     `json:"is_wifi7,omitempty"`
	IsRandomized bool     `json:"is_randomized,omitempty"`
	HasHandshake bool     `json:"has_handshake,omitempty"`
	ProbedSSIDs  []string `json:"probedSSIDs,omitempty"`
	IETags       []int    `json:"ieTags,omitempty"`
	WPSInfo      string   `json:"wps_info,omitempty"` // "Configured", "Unconfigured" or empty
}

// TrafficStats captures data transmission metrics.
type TrafficStats struct {
	DataTransmitted int64 `json:"data_tx"`
	DataReceived    int64 `json:"data_rx"`
	PacketsCount    int   `json:"packets"`
	RetryCount      int   `json:"retries"`
}

// NodeBehavioralData encapsulates higher-level analysis results.
type NodeBehavioralData struct {
	ProbeFrequency string  `json:"probeFreq,omitempty"`
	AnomalyScore   float64 `json:"anomalyScore,omitempty"`
	ActiveHours    []int   `json:"activeHours,omitempty"`
	Signature      string  `json:"signature,omitempty"`
	Model          string  `json:"model,omitempty"`
	OS             string  `json:"os,omitempty"`
}

// EdgeType defines the nature of the connection between nodes.
type EdgeType string

const (
	TypeConnection  EdgeType = "connection"
	TypeProbe       EdgeType = "probe"
	TypeCorrelation EdgeType = "correlation"
)

// GraphEdge represents a connection between two nodes.
type GraphEdge struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Dashed bool     `json:"dashed,omitempty"`
	Type   EdgeType `json:"type,omitempty"`
	Label  string   `json:"label,omitempty"` // For display
	Color  string   `json:"color,omitempty"` // Hex or rgba for dynamic override
}

// GraphData allows sending the whole graph state to the frontend.
type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}
