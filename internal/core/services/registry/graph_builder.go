package registry

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// GraphBuilder handles the construction of the visual graph.
type GraphBuilder struct {
	registry ports.DeviceRegistry
	config   *domain.GraphConfig
}

// NewGraphBuilder creates a new graph builder.
func NewGraphBuilder(registry ports.DeviceRegistry) *GraphBuilder {
	return &GraphBuilder{
		registry: registry,
		config:   domain.DefaultGraphConfig(),
	}
}

// BuildGraph generates the graph projection from the current registry state.
func (b *GraphBuilder) BuildGraph(ctx context.Context) domain.GraphData {
	devices := b.registry.GetAllDevices(ctx)
	ssids := b.registry.GetSSIDs(ctx)

	// Pre-allocate with a sensible heuristic:
	// Nodes: len(devices) + len(ssids) + possible stub nodes
	// Edges: at least len(devices) (probing/connecting)
	nodes := make([]domain.GraphNode, 0, len(devices)+len(ssids))
	edges := make([]domain.GraphEdge, 0, len(devices)*2)

	deviceMap := make(map[string]*domain.Device, len(devices))
	ssidInfo := make(map[string]*domain.GraphNode, len(ssids))

	// First pass: Build device map and collect representative AP data for SSID nodes
	for i := range devices {
		d := &devices[i]
		deviceMap[d.MAC] = d

		if d.Type == domain.DeviceTypeAP && d.SSID != "" {
			if existing, ok := ssidInfo[d.SSID]; !ok || d.LastSeen.After(existing.LastSeen) {
				ssidInfo[d.SSID] = &domain.GraphNode{
					NodeIdentity: domain.NodeIdentity{
						ID:        "ssid_" + d.SSID,
						Label:     d.SSID,
						Group:     domain.GroupNetwork,
						FirstSeen: d.FirstSeen,
						LastSeen:  d.LastSeen,
					},
					RadioDetails: domain.RadioDetails{
						SSID:      d.SSID,
						Security:  d.Security,
						Channel:   d.Channel,
						Frequency: d.Frequency,
					},
				}
			}
		}
	}

	// Add SSID nodes
	for ssid := range ssids {
		if info, ok := ssidInfo[ssid]; ok {
			nodes = append(nodes, *info)
		} else {
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

	// Second pass: Create device nodes and build edges
	for _, device := range devices {
		nodes = append(nodes, device.ToGraphNode())

		// --- Edge Logic ---

		// 1. Probing Edge (to SSID node)
		if device.SSID != "" {
			skipSSIDLink := false
			if device.ConnectedSSID != "" {
				if ap, ok := deviceMap[device.ConnectedSSID]; ok && ap.SSID == device.SSID {
					skipSSIDLink = true
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

		// 2. Extra Probed SSIDs
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

		// 3. Connection Edges
		if device.ConnectionTarget != "" && device.ConnectionState != domain.StateDisconnected {
			isDashed := false
			edgeLabel := ""
			switch device.ConnectionState {
			case domain.StateAuthenticating, domain.StateAssociating:
				isDashed = true
				edgeLabel = string(device.ConnectionState)
			case domain.StateHandshake:
				edgeLabel = "handshake"
			}

			if device.ConnectionError == "auth_failed" {
				isDashed = true
				edgeLabel = "auth failed"
			}

			var edgeColor string
			if device.ConnectionState == domain.StateConnected || device.ConnectionState == domain.StateHandshake {
				if device.RSSI > b.config.RSSIThresholds.Good {
					edgeColor = b.config.Colors.Good
				} else if device.RSSI > b.config.RSSIThresholds.Fair {
					edgeColor = b.config.Colors.Fair
				} else {
					edgeColor = b.config.Colors.Poor
				}
			}

			if device.ConnectionError == "auth_failed" {
				edgeColor = b.config.Colors.AuthFailed
			}

			edges = append(edges, domain.GraphEdge{
				From:   "dev_" + device.MAC,
				To:     "dev_" + device.ConnectionTarget,
				Type:   domain.TypeConnection,
				Dashed: isDashed,
				Label:  edgeLabel,
				Color:  edgeColor,
			})
		} else if device.ConnectedSSID != "" {
			edges = append(edges, domain.GraphEdge{
				From: "dev_" + device.MAC,
				To:   "dev_" + device.ConnectedSSID,
				Type: domain.TypeConnection,
			})
		}

	}

	// STUB NODES: Add nodes that are targets of edges but not in the registry
	referenced := make(map[string]struct{})
	for i := range edges {
		to := edges[i].To
		if len(to) > 4 && to[:4] == "dev_" {
			mac := to[4:]
			if _, exists := deviceMap[mac]; !exists {
				referenced[mac] = struct{}{}
			}
		}
	}

	for mac := range referenced {
		nodes = append(nodes, domain.GraphNode{
			NodeIdentity: domain.NodeIdentity{
				ID:     "dev_" + mac,
				Label:  "Unknown AP\n" + mac,
				Group:  domain.GroupAP,
				MAC:    mac,
				Vendor: "Unknown",
			},
			IsStale: true,
		})
	}

	return domain.GraphData{
		Nodes:  nodes,
		Edges:  edges,
		Config: b.config,
	}
}
