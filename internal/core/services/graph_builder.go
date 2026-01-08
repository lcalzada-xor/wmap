package services

import (
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// GraphBuilder handles the construction of the visual graph.
type GraphBuilder struct {
	registry ports.DeviceRegistry
}

// NewGraphBuilder creates a new graph builder.
func NewGraphBuilder(registry ports.DeviceRegistry) *GraphBuilder {
	return &GraphBuilder{
		registry: registry,
	}
}

// BuildGraph generates the graph projection from the current registry state.
func (b *GraphBuilder) BuildGraph() domain.GraphData {
	nodes := []domain.GraphNode{}
	edges := []domain.GraphEdge{}

	// Devices - First pass to collect SSID info from APs
	devices := b.registry.GetAllDevices()
	ssidInfo := make(map[string]*domain.GraphNode)

	for _, device := range devices {
		if device.Type == "ap" && device.SSID != "" {
			// Use the most recently seen AP for this SSID
			if existing, ok := ssidInfo[device.SSID]; !ok || device.LastSeen.After(existing.LastSeen) {
				ssidInfo[device.SSID] = &domain.GraphNode{
					ID:        "ssid_" + device.SSID,
					Label:     device.SSID,
					Group:     "network",
					SSID:      device.SSID,
					Security:  device.Security,
					Channel:   device.Channel,
					Frequency: device.Frequency,
					FirstSeen: device.FirstSeen,
					LastSeen:  device.LastSeen,
				}
			}
		}
	}

	// SSIDs - Add all SSIDs (including those without APs)
	ssids := b.registry.GetSSIDs()
	for ssid := range ssids {
		if info, ok := ssidInfo[ssid]; ok {
			nodes = append(nodes, *info)
		} else {
			// SSID without AP (only probed by stations)
			nodes = append(nodes, domain.GraphNode{
				ID:    "ssid_" + ssid,
				Label: ssid,
				Group: "network",
				SSID:  ssid,
			})
		}
	}

	// Devices - Second pass for device nodes
	for _, device := range devices {
		group := device.Type
		if group == "" {
			group = "station"
		}

		// Behavioral Details
		var probeFreqStr string
		var anomalyScore float64
		var activeHours []int
		if device.Behavioral != nil {
			if device.Behavioral.ProbeFrequency > 0 {
				probeFreqStr = device.Behavioral.ProbeFrequency.Round(time.Second).String()
			}
			anomalyScore = device.Behavioral.AnomalyScore
			activeHours = device.Behavioral.ActiveHours
		}

		label := device.MAC + "\n(" + device.Vendor + ")"
		if device.Frequency > 3000 {
			label += "\n[5GHz]"
		}

		nodes = append(nodes, domain.GraphNode{
			ID:           "dev_" + device.MAC,
			Label:        label,
			Group:        group,
			MAC:          device.MAC,
			Vendor:       device.Vendor,
			RSSI:         device.RSSI,
			LastSeen:     device.LastSeen,
			FirstSeen:    device.FirstSeen,
			Capabilities: device.Capabilities,
			IsRandomized: device.IsRandomized,
			HasHandshake: device.HasHandshake,
			SSID:         device.SSID,
			Channel:      device.Channel,
			Security:     device.Security,
			Standard:     device.Standard,
			Model:        device.Model,
			OS:           device.OS,
			Frequency:    device.Frequency,
			IsWiFi6:      device.IsWiFi6,
			IsWiFi7:      device.IsWiFi7,
			Signature:    device.Signature,
			WPSInfo:      device.WPSInfo,
			IETags:       device.IETags,

			// Traffic Stats
			DataTransmitted: device.DataTransmitted,
			DataReceived:    device.DataReceived,
			PacketsCount:    device.PacketsCount,
			RetryCount:      device.RetryCount,
			ChannelWidth:    device.ChannelWidth,

			// Behavioral
			ProbeFrequency: probeFreqStr,
			AnomalyScore:   anomalyScore,
			ActiveHours:    activeHours,
		})

		// SSID Edges (Logical Relation)
		if device.SSID != "" {
			// Skip direct SSID link if we're already connected to an AP that provides this SSID
			// to keep the graph cleaner.
			skipSSIDLink := false
			if device.ConnectedSSID != "" {
				if ap, ok := b.registry.GetDevice(device.ConnectedSSID); ok {
					if ap.SSID == device.SSID {
						skipSSIDLink = true
					}
				}
			}

			if !skipSSIDLink {
				edges = append(edges, domain.GraphEdge{
					From: "dev_" + device.MAC,
					To:   "ssid_" + device.SSID,
					Type: "probe",
				})
			}
		}

		for ssid := range device.ProbedSSIDs {
			if ssid != device.SSID {
				edges = append(edges, domain.GraphEdge{
					From:   "dev_" + device.MAC,
					To:     "ssid_" + ssid,
					Dashed: true,
					Type:   "probe",
				})
			}
		}

		// AP Connection Edges (Physical/Link Layer Connection)
		if device.ConnectedSSID != "" {
			edges = append(edges, domain.GraphEdge{
				From: "dev_" + device.MAC,
				To:   "dev_" + device.ConnectedSSID,
				Type: "connection",
			})
		} else if device.Behavioral != nil && device.Behavioral.LinkedMAC != "" {
			// INFERRED CONNECTION: Check if the linked device has a connection
			if linked, ok := b.registry.GetDevice(device.Behavioral.LinkedMAC); ok {
				if linked.ConnectedSSID != "" {
					edges = append(edges, domain.GraphEdge{
						From:   "dev_" + device.MAC,
						To:     "dev_" + linked.ConnectedSSID,
						Type:   "inferred",
						Dashed: true,
						Label:  "inferred assoc",
					})
				}
			}
		}

		// Correlation Edges (Randomization linkage)
		if device.Behavioral != nil && device.Behavioral.LinkedMAC != "" {
			edges = append(edges, domain.GraphEdge{
				From:   "dev_" + device.MAC,
				To:     "dev_" + device.Behavioral.LinkedMAC,
				Dashed: true,
				Type:   "correlation",
				Label:  "correlated",
			})
		}
	}

	return domain.GraphData{Nodes: nodes, Edges: edges}
}
