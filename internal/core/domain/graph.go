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
	ConnectionDetails

	// State and Metadata
	IsStale bool `json:"is_stale,omitempty"`
}

// NodeIdentity encapsulates basic identification and classification.
type NodeIdentity struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Group     GraphGroup `json:"group"` // "ap", "station", "network"
	MAC       string     `json:"mac,omitempty"`
	Vendor    string     `json:"vendor,omitempty"`
	Signature string     `json:"signature,omitempty"`
	Model     string     `json:"model,omitempty"`
	OS        string     `json:"os,omitempty"`
	FirstSeen time.Time  `json:"first_seen,omitempty"`
	LastSeen  time.Time  `json:"last_seen,omitempty"`
}

// RadioDetails encapsulates WiFi physical and link layer attributes.
type RadioDetails struct {
	// Strings and Slices (16-24 bytes)
	SSID          string   `json:"ssid,omitempty"`
	Security      string   `json:"security,omitempty"`
	Standard      string   `json:"standard,omitempty"`
	WPSInfo       string   `json:"wps_info,omitempty"` // "Configured", "Unconfigured" or empty
	HandshakeFile string   `json:"handshake_file,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	ProbedSSIDs   []string `json:"probedSSIDs,omitempty"`
	IETags        []int    `json:"ieTags,omitempty"`

	// Pointers (8 bytes)
	RSNInfo        *RSNInfo        `json:"rsn_info,omitempty"`
	WPSDetails     *WPSDetails     `json:"wps_details,omitempty"`
	MobilityDomain *MobilityDomain `json:"mobility_domain,omitempty"`

	// Numerics (8 bytes)
	Channel      int `json:"channel,omitempty"`
	ChannelWidth int `json:"bw"`
	Frequency    int `json:"frequency,omitempty"`
	RSSI         int `json:"rssi,omitempty"`

	// Booleans (1 byte)
	IsWiFi6      bool `json:"is_wifi6,omitempty"`
	IsWiFi7      bool `json:"is_wifi7,omitempty"`
	IsRandomized bool `json:"is_randomized,omitempty"`
	HasHandshake bool `json:"has_handshake,omitempty"`
}

// TrafficStats captures data transmission metrics.
type TrafficStats struct {
	DataTransmitted int64 `json:"data_tx"`
	DataReceived    int64 `json:"data_rx"`
	PacketsCount    int   `json:"packets"`
	RetryCount      int   `json:"retries"`
}


// ConnectionDetails captures current association state.
type ConnectionDetails struct {
	ConnectionState  ConnectionState `json:"connection_state,omitempty"`
	ConnectionTarget string          `json:"connection_target,omitempty"`
	ConnectionError  string          `json:"connection_error,omitempty"`
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
	Nodes  []GraphNode  `json:"nodes"`
	Edges  []GraphEdge  `json:"edges"`
	Config *GraphConfig `json:"config,omitempty"`
}

type GraphConfig struct {
	RSSIThresholds RSSIThresholds `json:"rssi_thresholds"`
	Colors         GraphColors    `json:"colors"`
}

type RSSIThresholds struct {
	Good int `json:"good"` // e.g. -65
	Fair int `json:"fair"` // e.g. -80
}

type GraphColors struct {
	Good       string `json:"good"`
	Fair       string `json:"fair"`
	Poor       string `json:"poor"`
	AuthFailed string `json:"auth_failed"`
}

func DefaultGraphConfig() *GraphConfig {
	return &GraphConfig{
		RSSIThresholds: RSSIThresholds{
			Good: -65,
			Fair: -80,
		},
		Colors: GraphColors{
			Good:       "#32d74b",
			Fair:       "#ffcc00",
			Poor:       "#ff453a",
			AuthFailed: "#ff453a",
		},
	}
}
