package domain

// InterfaceCapabilities helps the UI know what an interface supports.
type InterfaceCapabilities struct {
	SupportedBands    []string `json:"supported_bands"`    // e.g. ["2.4GHz", "5GHz"]
	SupportedChannels []int    `json:"supported_channels"` // e.g. [1, 2, ..., 36, 40...]
}

// InterfaceInfo represents a network interface and its state.
type InterfaceInfo struct {
	Name            string                `json:"name"`
	MAC             string                `json:"mac"`
	Capabilities    InterfaceCapabilities `json:"capabilities"`
	CurrentChannels []int                 `json:"current_channels"`
}
