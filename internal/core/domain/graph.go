package domain

import "time"

// GraphNode represents a node in the visualization graph.
type GraphNode struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Group        string    `json:"group"` // "ap", "station", "network"
	MAC          string    `json:"mac,omitempty"`
	Vendor       string    `json:"vendor,omitempty"`
	RSSI         int       `json:"rssi,omitempty"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	FirstSeen    time.Time `json:"first_seen,omitempty"`
	IsRandomized bool      `json:"isRandomized,omitempty"`
	ProbedSSIDs  []string  `json:"probedSSIDs,omitempty"`
	IETags       []int     `json:"ieTags,omitempty"`

	// New Fields
	SSID      string `json:"ssid,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	Security  string `json:"security,omitempty"`
	Standard  string `json:"standard,omitempty"`
	Model     string `json:"model,omitempty"`
	OS        string `json:"os,omitempty"`
	Frequency int    `json:"frequency,omitempty"`
	IsWiFi6   bool   `json:"is_wifi6,omitempty"`
	IsWiFi7   bool   `json:"is_wifi7,omitempty"`

	DataTransmitted int64  `json:"data_tx"`
	DataReceived    int64  `json:"data_rx"`
	PacketsCount    int    `json:"packets"`
	RetryCount      int    `json:"retries"`
	ChannelWidth    int    `json:"bw"`
	Signature       string `json:"signature,omitempty"`
	WPSInfo         string `json:"wps_info,omitempty"` // "Configured", "Unconfigured" or empty

	// Behavioral Intelligence (Phase A)
	ProbeFrequency string  `json:"probeFreq,omitempty"`
	AnomalyScore   float64 `json:"anomalyScore,omitempty"`
	ActiveHours    []int   `json:"activeHours,omitempty"`

	Title string `json:"title,omitempty"` // Tooltip/Popup content
}

// GraphEdge represents a connection between two nodes.
type GraphEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Dashed bool   `json:"dashed,omitempty"`
	Type   string `json:"type,omitempty"`  // "connection", "probe", "correlation"
	Label  string `json:"label,omitempty"` // For display
}

// GraphData allows sending the whole graph state to the frontend
type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}
