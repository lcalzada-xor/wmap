package domain

import (
	"errors"
)

// WiFiBand represents a typed string for frequency bands.
type WiFiBand string

const (
	Band24GHz WiFiBand = "2.4GHz"
	Band5GHz  WiFiBand = "5GHz"
	Band6GHz  WiFiBand = "6GHz"
)

// Domain Errors for network interfaces.
var (
	ErrInvalidInterfaceName = errors.New("invalid interface name")
	ErrInvalidMAC           = errors.New("invalid MAC address")
	ErrUnsupportedBand      = errors.New("unsupported wifi band")
)

// InterfaceCapabilities helps the UI know what an interface supports.
type InterfaceCapabilities struct {
	SupportedBands    []WiFiBand `json:"supported_bands"`
	SupportedChannels []int      `json:"supported_channels"`
}

// InterfaceInfo represents a network interface and its state.
type InterfaceInfo struct {
	Name            string                `json:"name"`
	MAC             string                `json:"mac"`
	Capabilities    InterfaceCapabilities `json:"capabilities"`
	CurrentChannels []int                 `json:"current_channels"`
	Metrics         InterfaceMetrics      `json:"metrics"`
}

// InterfaceMetrics holds packet capture statistics.
type InterfaceMetrics struct {
	PacketsReceived   int64 `json:"packets_received"`
	PacketsDropped    int64 `json:"packets_dropped"`
	AppPacketsDropped int64 `json:"app_packets_dropped"` // Buffer full
	PacketsIfDropped  int64 `json:"packets_if_dropped"`  // Interface drops
	ErrorCount        int64 `json:"error_count"`         // Processing errors
}

// NewInterfaceInfo is the factory for creating valid InterfaceInfo entities.
func NewInterfaceInfo(name, mac string, caps InterfaceCapabilities) (*InterfaceInfo, error) {
	if !IsValidInterface(name) {
		return nil, ErrInvalidInterfaceName
	}

	if !IsValidMAC(mac) {
		return nil, ErrInvalidMAC
	}

	return &InterfaceInfo{
		Name:            name,
		MAC:             mac,
		Capabilities:    caps,
		CurrentChannels: make([]int, 0),
		Metrics:         InterfaceMetrics{},
	}, nil
}

// UpdateChannels updates the currently active channels for this interface.
func (i *InterfaceInfo) UpdateChannels(channels []int) {
	i.CurrentChannels = channels
}

// ResetMetrics clears all counters.
func (m *InterfaceMetrics) ResetMetrics() {
	m.PacketsReceived = 0
	m.PacketsDropped = 0
	m.AppPacketsDropped = 0
	m.PacketsIfDropped = 0
	m.ErrorCount = 0
}

// AddMetrics increments metrics from another source (e.g., from a capture session).
func (m *InterfaceMetrics) AddMetrics(other InterfaceMetrics) {
	m.PacketsReceived += other.PacketsReceived
	m.PacketsDropped += other.PacketsDropped
	m.AppPacketsDropped += other.AppPacketsDropped
	m.PacketsIfDropped += other.PacketsIfDropped
	m.ErrorCount += other.ErrorCount
}
