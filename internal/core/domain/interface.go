package domain

import (
	"errors"
	"strings"
	"sync"
)

// WiFiBand represents a typed string for frequency bands.
type WiFiBand string

const (
	Band24GHz WiFiBand = "2.4GHz"
	Band5GHz  WiFiBand = "5GHz"
	Band6GHz  WiFiBand = "6GHz"
)

// OperationMode represents the operational state of the wireless interface.
type OperationMode string

const (
	ModeManaged OperationMode = "managed"
	ModeMonitor OperationMode = "monitor"
	ModeMaster  OperationMode = "master" // AP
	ModeAdHoc   OperationMode = "ad-hoc"
	ModeUnknown OperationMode = "unknown"
)

// Domain Errors for network interfaces.
var (
	ErrInvalidInterfaceName = errors.New("invalid interface name")
	ErrInvalidMAC           = errors.New("invalid MAC address")
	ErrInvalidSSID          = errors.New("invalid SSID")
	ErrUnsupportedBand      = errors.New("unsupported wifi band")
)

type InterfaceCapabilities struct {
	SupportedBands    []WiFiBand    `json:"supported_bands"`
	SupportedChannels []int         `json:"supported_channels"`
	DriverName        string        `json:"driver_name,omitempty"`    // e.g., "iwlwifi"
	TxPower           int           `json:"tx_power,omitempty"`       // dBm
	OperationMode     OperationMode `json:"operation_mode,omitempty"` // e.g., "managed", "monitor"
}

// InterfaceInfo represents a network interface and its state.
type InterfaceInfo struct {
	mu sync.RWMutex // Protects concurrently accessed fields

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
// It normalizes the MAC address to lowercase.
func NewInterfaceInfo(name, mac string, caps InterfaceCapabilities) (*InterfaceInfo, error) {
	if !IsValidInterface(name) {
		return nil, ErrInvalidInterfaceName
	}

	if !IsValidMAC(mac) {
		return nil, ErrInvalidMAC
	}

	normMAC := strings.ToLower(mac)

	return &InterfaceInfo{
		Name:            name,
		MAC:             normMAC,
		Capabilities:    caps,
		CurrentChannels: make([]int, 0),
		Metrics:         InterfaceMetrics{},
	}, nil
}

// UpdateChannels updates the currently active channels for this interface with a deep copy.
func (i *InterfaceInfo) UpdateChannels(channels []int) {
	i.mu.Lock()
	defer i.mu.Unlock()

	cp := make([]int, len(channels))
	copy(cp, channels)
	i.CurrentChannels = cp
}

// GetChannels returns a safe copy of the current channels.
func (i *InterfaceInfo) GetChannels() []int {
	i.mu.RLock()
	defer i.mu.RUnlock()

	cp := make([]int, len(i.CurrentChannels))
	copy(cp, i.CurrentChannels)
	return cp
}

// GetMetrics returns a copy of the current metrics.
func (i *InterfaceInfo) GetMetrics() InterfaceMetrics {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.Metrics
}

// ResetMetrics clears all counters.
func (i *InterfaceInfo) ResetMetrics() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Metrics.ResetMetrics()
}

// AddMetrics increments metrics from another source safely.
func (i *InterfaceInfo) AddMetrics(other InterfaceMetrics) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Metrics.AddMetrics(other)
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
