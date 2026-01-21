package domain

import (
	"errors"
	"time"
)

// TrafficPattern represents the categorized network traffic behavior.
type TrafficPattern string

const (
	TrafficPatternBursty   TrafficPattern = "bursty"
	TrafficPatternPeriodic TrafficPattern = "periodic"
	TrafficPatternConstant TrafficPattern = "constant"
	TrafficPatternUnknown  TrafficPattern = "unknown"
)

// MetricType defines the supported behavioral metrics.
type MetricType string

const (
	MetricTypeProbe   MetricType = "probe"
	MetricTypeTraffic MetricType = "traffic"
	MetricTypeRoaming MetricType = "roaming"
	MetricTypeSignal  MetricType = "signal"
)

// AnomalyDetails maps anomaly subtypes to their influence score [0.0 - 1.0].
type AnomalyDetails map[string]float64

// BehavioralProfile encapsulates the behavioral fingerprints of a wireless device.
// It moves from anemic data structure to a rich domain entity.
type BehavioralProfile struct {
	MAC            string         `json:"mac"`
	ProbeFrequency time.Duration  `json:"probe_frequency"` // Moving average of time between probe requests
	UniqueSSIDs    int            `json:"unique_ssids"`    // Count of distinct SSIDs observed
	RoamingScore   float64        `json:"roaming_score"`   // 0.0=stationary, 1.0=aggresive roaming
	PowerSaveMode  bool           `json:"power_save_mode"` // Presence of PM bits in frames
	TrafficPattern TrafficPattern `json:"traffic_pattern"`
	ActiveHours    []int          `json:"active_hours"`  // Bitmask or slice of hours [0-23]
	AnomalyScore   float64        `json:"anomaly_score"` // Normalized threat/anomaly indicator [0.0 - 1.0]
	AnomalyDetails AnomalyDetails `json:"anomaly_details"`
	SSIDSignature  string         `json:"ssid_signature"` // Sorted hash/string for device correlation
	IETags         []int          `json:"ie_tags"`        // IEEE 802.11 Information Element fingerprints
	LinkedMAC      string         `json:"linked_mac"`     // Correlated real MAC (for randomized identities)
	LastUpdated    time.Time      `json:"last_updated"`

	// Internal state tracking (unexported from JSON)
	lastProbeTime time.Time
}

// NewBehavioralProfile creates a default initialized profile for a MAC address.
func NewBehavioralProfile(mac string) *BehavioralProfile {
	return &BehavioralProfile{
		MAC:            mac,
		ActiveHours:    make([]int, 0),
		AnomalyDetails: make(AnomalyDetails),
		TrafficPattern: TrafficPatternUnknown,
		LastUpdated:    time.Now(),
	}
}

// RecordProbe updates frequency metrics based on a new observation.
// It uses an Exponential Moving Average (EMA) to weight recent behavior.
func (p *BehavioralProfile) RecordProbe(observedAt time.Time) {
	if !p.lastProbeTime.IsZero() {
		interval := observedAt.Sub(p.lastProbeTime)
		if interval > 0 {
			if p.ProbeFrequency == 0 {
				p.ProbeFrequency = interval
			} else {
				// 70% weight to history, 30% to new interval
				p.ProbeFrequency = time.Duration(float64(p.ProbeFrequency)*0.7 + float64(interval)*0.3)
			}
		}
	}
	p.lastProbeTime = observedAt
	p.LastUpdated = time.Now()
}

// RecordActivity ensures the current hour is tracked in the device's active schedule.
func (p *BehavioralProfile) RecordActivity(at time.Time) {
	hour := at.Hour()
	for _, h := range p.ActiveHours {
		if h == hour {
			return
		}
	}
	p.ActiveHours = append(p.ActiveHours, hour)
	p.LastUpdated = time.Now()
}

// SetAnomaly updates a specific anomaly metric and recalculates the global score.
func (p *BehavioralProfile) SetAnomaly(subtype string, contribution float64) {
	if contribution < 0 {
		contribution = 0
	} else if contribution > 1 {
		contribution = 1
	}

	if p.AnomalyDetails == nil {
		p.AnomalyDetails = make(AnomalyDetails)
	}
	p.AnomalyDetails[subtype] = contribution
	p.recalculateAnomalyScore()
}

// recalculateAnomalyScore derives the global score from individual details.
// Strategy: Currently uses the maximum contribution as the primary indicator.
func (p *BehavioralProfile) recalculateAnomalyScore() {
	max := 0.0
	for _, val := range p.AnomalyDetails {
		if val > max {
			max = val
		}
	}
	p.AnomalyScore = max
	p.LastUpdated = time.Now()
}

// Validate performs structural and domain integrity checks.
func (p *BehavioralProfile) Validate() error {
	if p.MAC == "" {
		return errors.New("behavioral profile must have a valid MAC")
	}
	if p.RoamingScore < 0 || p.RoamingScore > 1 {
		return errors.New("roaming score must be between 0.0 and 1.0")
	}
	if p.AnomalyScore < 0 || p.AnomalyScore > 1 {
		return errors.New("anomaly score must be between 0.0 and 1.0")
	}
	return nil
}

// DeviceMetric represents a discrete behavioral observation for time-series analysis.
type DeviceMetric struct {
	Timestamp  time.Time              `json:"timestamp"`
	MAC        string                 `json:"mac"`
	MetricType MetricType             `json:"metric_type"`
	Value      float64                `json:"value"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}
