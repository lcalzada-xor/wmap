package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/services/registry"
	"github.com/stretchr/testify/assert"
)

// TestConnectionStateFlow_Integration tests the complete flow from device processing to graph building
func TestConnectionStateFlow_Integration(t *testing.T) {
	// 1. Create registry and graph builder
	reg := registry.NewDeviceRegistry(nil)
	builder := registry.NewGraphBuilder(reg)

	// 2. Create AP device
	ap := domain.Device{
		MAC:            "00:11:22:33:44:55",
		Type:           "ap",
		SSID:           "TestNetwork",
		LastPacketTime: time.Now(),
	}
	reg.ProcessDevice(ap)

	// 3. Create Station device with connection state
	station := domain.Device{
		MAC:              "aa:bb:cc:dd:ee:ff",
		Type:             "station",
		ConnectionState:  domain.StateConnected,
		ConnectionTarget: "00:11:22:33:44:55", // Connected to AP
		LastPacketTime:   time.Now(),
	}
	merged, _ := reg.ProcessDevice(station)

	// 4. Verify device was merged correctly
	assert.Equal(t, domain.StateConnected, merged.ConnectionState, "ConnectionState should be preserved")
	assert.Equal(t, "00:11:22:33:44:55", merged.ConnectionTarget, "ConnectionTarget should be preserved")

	// 5. Build graph
	graph := builder.BuildGraph()

	// 6. Verify nodes exist
	var apNode, stationNode *domain.GraphNode
	for i := range graph.Nodes {
		if graph.Nodes[i].ID == "dev_00:11:22:33:44:55" {
			apNode = &graph.Nodes[i]
		}
		if graph.Nodes[i].ID == "dev_aa:bb:cc:dd:ee:ff" {
			stationNode = &graph.Nodes[i]
		}
	}

	assert.NotNil(t, apNode, "AP node should exist in graph")
	assert.NotNil(t, stationNode, "Station node should exist in graph")

	// 7. Verify connection edge exists
	var connectionEdge *domain.GraphEdge
	for i := range graph.Edges {
		if graph.Edges[i].From == "dev_aa:bb:cc:dd:ee:ff" &&
			graph.Edges[i].To == "dev_00:11:22:33:44:55" &&
			graph.Edges[i].Type == "connection" {
			connectionEdge = &graph.Edges[i]
			break
		}
	}

	assert.NotNil(t, connectionEdge, "Connection edge should exist between station and AP")
	if connectionEdge != nil {
		assert.False(t, connectionEdge.Dashed, "Connected edge should be solid (not dashed)")
		assert.NotEmpty(t, connectionEdge.Color, "Edge should have RSSI-based color")
	}

	// 8. Print debug info if test fails
	if connectionEdge == nil {
		t.Logf("Graph has %d nodes and %d edges", len(graph.Nodes), len(graph.Edges))
		t.Logf("Station device: ConnectionState=%s, ConnectionTarget=%s",
			merged.ConnectionState, merged.ConnectionTarget)
		for _, edge := range graph.Edges {
			t.Logf("Edge: %s -> %s (type: %s)", edge.From, edge.To, edge.Type)
		}
	}
}

// TestConnectionStateFlow_AllStates tests all connection states create appropriate edges
func TestConnectionStateFlow_AllStates(t *testing.T) {
	testCases := []struct {
		name           string
		state          string
		expectedDashed bool
		expectedLabel  string
	}{
		{
			name:           "Authenticating",
			state:          domain.StateAuthenticating,
			expectedDashed: true,
			expectedLabel:  "authenticating",
		},
		{
			name:           "Associating",
			state:          domain.StateAssociating,
			expectedDashed: true,
			expectedLabel:  "associating",
		},
		{
			name:           "Handshake",
			state:          domain.StateHandshake,
			expectedDashed: false,
			expectedLabel:  "handshake",
		},
		{
			name:           "Connected",
			state:          domain.StateConnected,
			expectedDashed: false,
			expectedLabel:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reg := registry.NewDeviceRegistry(nil)
			builder := registry.NewGraphBuilder(reg)

			// Create AP
			ap := domain.Device{
				MAC:            "00:11:22:33:44:55",
				Type:           "ap",
				LastPacketTime: time.Now(),
			}
			reg.ProcessDevice(ap)

			// Create Station with specific state
			station := domain.Device{
				MAC:              "aa:bb:cc:dd:ee:ff",
				Type:             "station",
				ConnectionState:  tc.state,
				ConnectionTarget: "00:11:22:33:44:55",
				RSSI:             -50, // Good signal
				LastPacketTime:   time.Now(),
			}
			reg.ProcessDevice(station)

			// Build graph
			graph := builder.BuildGraph()

			// Find edge
			var edge *domain.GraphEdge
			for i := range graph.Edges {
				if graph.Edges[i].Type == "connection" {
					edge = &graph.Edges[i]
					break
				}
			}

			assert.NotNil(t, edge, "Edge should exist for state: %s", tc.state)
			if edge != nil {
				assert.Equal(t, tc.expectedDashed, edge.Dashed,
					"Dashed property mismatch for state: %s", tc.state)
				assert.Equal(t, tc.expectedLabel, edge.Label,
					"Label mismatch for state: %s", tc.state)
			}
		})
	}
}

// TestConnectionStateFlow_Disconnected verifies disconnected state does NOT create edge
func TestConnectionStateFlow_Disconnected(t *testing.T) {
	reg := registry.NewDeviceRegistry(nil)
	builder := registry.NewGraphBuilder(reg)

	// Create AP
	ap := domain.Device{
		MAC:            "00:11:22:33:44:55",
		Type:           "ap",
		LastPacketTime: time.Now(),
	}
	reg.ProcessDevice(ap)

	// Create disconnected station
	station := domain.Device{
		MAC:              "aa:bb:cc:dd:ee:ff",
		Type:             "station",
		ConnectionState:  domain.StateDisconnected,
		ConnectionTarget: "", // No target when disconnected
		LastPacketTime:   time.Now(),
	}
	reg.ProcessDevice(station)

	// Build graph
	graph := builder.BuildGraph()

	// Verify NO connection edge exists
	for _, edge := range graph.Edges {
		if edge.Type == "connection" {
			t.Errorf("Should NOT create connection edge for disconnected state")
		}
	}
}
