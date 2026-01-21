package registry

import (
	"context"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
)

// GraphBuilder handles the construction of the visual graph.
type GraphBuilder struct {
	registry              ports.DeviceRegistry
	vulnerabilityDetector *security.VulnerabilityDetector
}

// NewGraphBuilder creates a new graph builder.
func NewGraphBuilder(registry ports.DeviceRegistry) *GraphBuilder {
	return &GraphBuilder{
		registry:              registry,
		vulnerabilityDetector: security.NewVulnerabilityDetector(registry),
	}
}

// BuildGraph generates the graph projection from the current registry state.
func (b *GraphBuilder) BuildGraph(ctx context.Context) domain.GraphData {
	nodes := []domain.GraphNode{}
	edges := []domain.GraphEdge{}

	// Devices - First pass to collect SSID info from APs
	devices := b.registry.GetAllDevices(ctx)

	// properties for O(1) lookup
	deviceMap := make(map[string]*domain.Device)
	for i := range devices {
		deviceMap[devices[i].MAC] = &devices[i]
	}

	ssidInfo := make(map[string]*domain.GraphNode)

	for _, device := range devices {
		if device.Type == "ap" && device.SSID != "" {
			// Use the most recently seen AP for this SSID
			if existing, ok := ssidInfo[device.SSID]; !ok || device.LastSeen.After(existing.LastSeen) {
				ssidInfo[device.SSID] = &domain.GraphNode{
					NodeIdentity: domain.NodeIdentity{
						ID:        "ssid_" + device.SSID,
						Label:     device.SSID,
						Group:     domain.GroupNetwork,
						FirstSeen: device.FirstSeen,
						LastSeen:  device.LastSeen,
					},
					RadioDetails: domain.RadioDetails{
						SSID:      device.SSID,
						Security:  device.Security,
						Channel:   device.Channel,
						Frequency: device.Frequency,
					},
				}
			}
		}
	}

	// SSIDs - Add all SSIDs (including those without APs)
	ssids := b.registry.GetSSIDs(ctx)
	for ssid := range ssids {
		if info, ok := ssidInfo[ssid]; ok {
			nodes = append(nodes, *info)
		} else {
			// SSID without AP (only probed by stations)
			nodes = append(nodes, domain.GraphNode{
				NodeIdentity: domain.NodeIdentity{
					ID:    "ssid_" + ssid,
					Label: ssid,
					Group: domain.GroupNetwork,
				},
				RadioDetails: domain.RadioDetails{
					SSID: ssid,
				},
			})
		}
	}

	// Devices - Second pass for device nodes
	for _, device := range devices {
		group := domain.GraphGroup(device.Type)
		if group == "" {
			group = domain.GroupStation
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

		// Passive Vulnerability Detection
		vulns := b.vulnerabilityDetector.DetectVulnerabilities(&device)

		nodes = append(nodes, domain.GraphNode{
			NodeIdentity: domain.NodeIdentity{
				ID:        "dev_" + device.MAC,
				Label:     label,
				Group:     group,
				MAC:       device.MAC,
				Vendor:    device.Vendor,
				LastSeen:  device.LastSeen,
				FirstSeen: device.FirstSeen,
			},
			RadioDetails: domain.RadioDetails{
				RSSI:         device.RSSI,
				Capabilities: device.Capabilities,
				IsRandomized: device.IsRandomized,
				HasHandshake: device.HasHandshake,
				SSID:         device.SSID,
				Channel:      device.Channel,
				Security:     device.Security,
				Standard:     device.Standard,
				Frequency:    device.Frequency,
				IsWiFi6:      device.IsWiFi6,
				IsWiFi7:      device.IsWiFi7,
				WPSInfo:      device.WPSInfo,
				IETags:       device.IETags,
			},
			TrafficStats: domain.TrafficStats{
				DataTransmitted: device.DataTransmitted,
				DataReceived:    device.DataReceived,
				PacketsCount:    device.PacketsCount,
				RetryCount:      device.RetryCount,
			},
			NodeBehavioralData: domain.NodeBehavioralData{
				ProbeFrequency: probeFreqStr,
				AnomalyScore:   anomalyScore,
				ActiveHours:    activeHours,
				Signature:      device.Signature,
				Model:          device.Model,
				OS:             device.OS,
			},
			Vulnerabilities: vulns,
		})

		// SSID Edges (Logical Relation)
		if device.SSID != "" {
			// Skip direct SSID link if we're already connected to an AP that provides this SSID
			// to keep the graph cleaner.
			skipSSIDLink := false
			if device.ConnectedSSID != "" {
				if ap, ok := deviceMap[device.ConnectedSSID]; ok {
					if ap.SSID == device.SSID {
						skipSSIDLink = true
					}
				}
			}

			if !skipSSIDLink {
				edges = append(edges, domain.GraphEdge{
					From: "dev_" + device.MAC,
					To:   "ssid_" + device.SSID,
					Type: domain.TypeProbe,
				})
			}
		}

		for ssid := range device.ProbedSSIDs {
			if ssid != device.SSID {
				edges = append(edges, domain.GraphEdge{
					From:   "dev_" + device.MAC,
					To:     "ssid_" + ssid,
					Dashed: true,
					Type:   domain.TypeProbe,
				})
			}
		}

		// AP Connection Edges (Physical/Link Layer Connection)
		if device.ConnectionTarget != "" && device.ConnectionState != domain.StateDisconnected {
			edgeType := domain.TypeConnection
			isDashed := false
			edgeLabel := ""

			if device.ConnectionState == domain.StateAuthenticating {
				isDashed = true
				edgeLabel = "authenticating"
			} else if device.ConnectionState == domain.StateAssociating {
				isDashed = true
				edgeLabel = "associating"
			} else if device.ConnectionState == domain.StateHandshake {
				edgeLabel = "handshake"
			}

			// Auth Failure Override
			if device.ConnectionError == "auth_failed" {
				isDashed = true
				edgeLabel = "auth failed"
				// Red color will be handled by setting Color explicitly
			}

			var edgeColor string
			// Dynamic RSSI Coloring for active connections
			if device.ConnectionState == domain.StateConnected || device.ConnectionState == domain.StateHandshake {
				if device.RSSI > -65 {
					edgeColor = "#32d74b" // Green (Excellent)
				} else if device.RSSI > -80 {
					edgeColor = "#ffcc00" // Yellow (Fair)
				} else {
					edgeColor = "#ff453a" // Red (Poor)
				}
			}

			// Auth Failure Red Override
			if device.ConnectionError == "auth_failed" {
				edgeColor = "#ff453a" // Red
			}

			edges = append(edges, domain.GraphEdge{
				From:   "dev_" + device.MAC,
				To:     "dev_" + device.ConnectionTarget,
				Type:   edgeType,
				Dashed: isDashed,
				Label:  edgeLabel,
				Color:  edgeColor,
			})
		} else if device.ConnectedSSID != "" {
			// Legacy/Fallback for devices without precise state yet
			edges = append(edges, domain.GraphEdge{
				From: "dev_" + device.MAC,
				To:   "dev_" + device.ConnectedSSID,
				Type: domain.TypeConnection,
			})
		} else if device.Behavioral != nil && device.Behavioral.LinkedMAC != "" {
			// INFERRED CONNECTION: Check if the linked device has a connection
			if linked, ok := deviceMap[device.Behavioral.LinkedMAC]; ok {
				if linked.ConnectedSSID != "" {
					edges = append(edges, domain.GraphEdge{
						From:   "dev_" + device.MAC,
						To:     "dev_" + linked.ConnectedSSID,
						Type:   domain.TypeConnection,
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
				Type:   domain.TypeCorrelation,
				Label:  "correlated",
			})
		}
	}

	// STUB NODES: Check for referenced edges to missing nodes
	referenced := make(map[string]bool)
	for _, e := range edges {
		// We only care about connection targets (dev_ to dev_)
		if len(e.To) > 4 && e.To[:4] == "dev_" {
			mac := e.To[4:]
			referenced[mac] = true
		}
	}

	for mac := range referenced {
		if _, exists := deviceMap[mac]; !exists {
			// Create Stub Node
			nodes = append(nodes, domain.GraphNode{
				NodeIdentity: domain.NodeIdentity{
					ID:     "dev_" + mac,
					Label:  "Unknown AP\n" + mac,
					Group:  domain.GroupAP, // Assume AP if it's a target
					MAC:    mac,
					Vendor: "Unknown",
				},
				IsStale: true, // Visual cue
			})
		}
	}

	return domain.GraphData{Nodes: nodes, Edges: edges}
}
