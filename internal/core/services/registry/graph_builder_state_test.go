package registry

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGraphBuilder_AllConnectionStatesRendered ensures that ALL connection states
// are properly rendered in the graph builder. This test will FAIL if a new state
// is added but not handled in the graph builder logic.
func TestGraphBuilder_AllConnectionStatesRendered(t *testing.T) {
	staMAC := "00:11:22:33:44:55"
	apMAC := "aa:bb:cc:dd:ee:ff"

	// Test all connection states
	testCases := []struct {
		name          string
		state         domain.ConnectionState
		expectEdge    bool
		expectDashed  bool
		expectedLabel string
	}{
		{
			name:          "StateAuthenticating",
			state:         domain.StateAuthenticating,
			expectEdge:    true,
			expectDashed:  true,
			expectedLabel: "authenticating",
		},
		{
			name:          "StateAssociating",
			state:         domain.StateAssociating,
			expectEdge:    true,
			expectDashed:  true,
			expectedLabel: "associating",
		},
		{
			name:          "StateHandshake",
			state:         domain.StateHandshake,
			expectEdge:    true,
			expectDashed:  false,
			expectedLabel: "handshake",
		},
		{
			name:          "StateConnected",
			state:         domain.StateConnected,
			expectEdge:    true,
			expectDashed:  false,
			expectedLabel: "",
		},
		{
			name:       "StateDisconnected",
			state:      domain.StateDisconnected,
			expectEdge: false, // Disconnected should NOT create an edge
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create fresh registry for each test case to avoid state pollution
			registry := NewDeviceRegistry(nil, nil)
			builder := NewGraphBuilder(registry)

			// Register AP first
			ap := domain.Device{
				MAC:       apMAC,
				Type:      "ap",
				SSID:      "TestAP",
				LastSeen:  time.Now(),
				FirstSeen: time.Now(),
			}
			registry.ProcessDevice(context.Background(), ap)

			// Create station with specific connection state
			sta := domain.Device{
				MAC:              staMAC,
				Type:             "station",
				ConnectionState:  tc.state,
				ConnectionTarget: apMAC,
				LastSeen:         time.Now(),
				FirstSeen:        time.Now(),
				RSSI:             -50,
			}
			registry.ProcessDevice(context.Background(), sta)

			// Build graph
			graph := builder.BuildGraph(context.Background())

			// Find edge from station to AP
			var foundEdge *domain.GraphEdge
			for i := range graph.Edges {
				if graph.Edges[i].From == "dev_"+staMAC && graph.Edges[i].To == "dev_"+apMAC {
					foundEdge = &graph.Edges[i]
					break
				}
			}

			if tc.expectEdge {
				require.NotNil(t, foundEdge, "Expected edge for state %s but none found", tc.state)
				assert.Equal(t, tc.expectDashed, foundEdge.Dashed,
					"State %s: expected Dashed=%v but got %v", tc.state, tc.expectDashed, foundEdge.Dashed)
				if tc.expectedLabel != "" {
					assert.Equal(t, tc.expectedLabel, foundEdge.Label,
						"State %s: expected Label=%s but got %s", tc.state, tc.expectedLabel, foundEdge.Label)
				}
			} else {
				assert.Nil(t, foundEdge, "Expected NO edge for state %s but found one", tc.state)
			}
		})
	}
}
