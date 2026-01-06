package domain

import "time"

// BehavioralProfile represents behavioral patterns of a device
type BehavioralProfile struct {
	MAC            string             `json:"mac"`
	ProbeFrequency time.Duration      `json:"probe_frequency"` // Average time between probe requests
	UniqueSSIDs    int                `json:"unique_ssids"`    // Number of unique SSIDs probed
	RoamingScore   float64            `json:"roaming_score"`   // 0=sticky, 1=aggressive roaming
	PowerSaveMode  bool               `json:"power_save_mode"` // Uses power save features
	TrafficPattern string             `json:"traffic_pattern"` // "bursty", "periodic", "constant"
	ActiveHours    []int              `json:"active_hours"`    // Hours of day when active [0-23]
	AnomalyScore   float64            `json:"anomaly_score"`   // 0=normal, 1=highly anomalous
	AnomalyDetails map[string]float64 `json:"anomaly_details"` // Subtype -> Contribution
	SSIDSignature  string             `json:"ssid_signature"`  // Hash of probed SSIDs for correlation
	IETags         []int              `json:"ie_tags"`         // IE fingerprints for correlation
	LinkedMAC      string             `json:"linked_mac"`      // MAC of a correlated device (randomization)
	LastUpdated    time.Time          `json:"last_updated"`
	LastProbeTime  time.Time          `json:"-"` // Internal use for frequency calculation
}

// DeviceMetric represents a single time-series metric for a device
type DeviceMetric struct {
	Time       time.Time              `json:"time"`
	MAC        string                 `json:"mac"`
	MetricType string                 `json:"metric_type"` // "probe", "traffic", "roaming", "signal"
	Value      float64                `json:"value"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Metric type constants
const (
	MetricTypeProbe   = "probe"
	MetricTypeTraffic = "traffic"
	MetricTypeRoaming = "roaming"
	MetricTypeSignal  = "signal"
)
