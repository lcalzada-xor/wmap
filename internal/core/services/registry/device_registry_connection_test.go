package registry

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

// TestDeviceRegistry_MergeConnectionState verifies that connection state fields
// are properly merged when processing an existing device.
func TestDeviceRegistry_MergeConnectionState(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)
	mac := "AA:BB:CC:DD:EE:FF"
	apMAC := "00:11:22:33:44:55"

	// Step 1: Initial device with no connection state
	dev1 := domain.Device{
		MAC:             mac,
		Type:            "station",
		LastPacketTime:  time.Now().Add(-10 * time.Second),
		ConnectionState: domain.StateDisconnected,
	}
	registry.ProcessDevice(context.Background(), dev1)

	stored, _ := registry.GetDevice(context.Background(), mac)
	assert.Equal(t, domain.StateDisconnected, stored.ConnectionState)
	assert.Equal(t, "", stored.ConnectionTarget)

	// Step 2: Device sends Authentication frame
	dev2 := domain.Device{
		MAC:              mac,
		Type:             "station",
		LastPacketTime:   time.Now().Add(-8 * time.Second),
		ConnectionState:  domain.StateAuthenticating,
		ConnectionTarget: apMAC,
	}
	registry.ProcessDevice(context.Background(), dev2)

	stored, _ = registry.GetDevice(context.Background(), mac)
	assert.Equal(t, domain.StateAuthenticating, stored.ConnectionState, "Should update to Authenticating state")
	assert.Equal(t, apMAC, stored.ConnectionTarget, "Should set ConnectionTarget to AP MAC")

	// Step 3: Device sends Association Request
	dev3 := domain.Device{
		MAC:              mac,
		Type:             "station",
		LastPacketTime:   time.Now().Add(-5 * time.Second),
		ConnectionState:  domain.StateAssociating,
		ConnectionTarget: apMAC,
	}
	registry.ProcessDevice(context.Background(), dev3)

	stored, _ = registry.GetDevice(context.Background(), mac)
	assert.Equal(t, domain.StateAssociating, stored.ConnectionState, "Should update to Associating state")
	assert.Equal(t, apMAC, stored.ConnectionTarget, "Should maintain ConnectionTarget")

	// Step 4: Device completes connection (data frames)
	dev4 := domain.Device{
		MAC:              mac,
		Type:             "station",
		LastPacketTime:   time.Now().Add(-2 * time.Second),
		ConnectionState:  domain.StateConnected,
		ConnectionTarget: apMAC,
	}
	registry.ProcessDevice(context.Background(), dev4)

	stored, _ = registry.GetDevice(context.Background(), mac)
	assert.Equal(t, domain.StateConnected, stored.ConnectionState, "Should update to Connected state")
	assert.Equal(t, apMAC, stored.ConnectionTarget, "Should maintain ConnectionTarget")

	// Step 5: Connection fails (auth failure)
	dev5 := domain.Device{
		MAC:              mac,
		Type:             "station",
		LastPacketTime:   time.Now(),
		ConnectionState:  domain.StateDisconnected,
		ConnectionError:  "auth_failed",
		ConnectionTarget: "",
	}
	registry.ProcessDevice(context.Background(), dev5)

	stored, _ = registry.GetDevice(context.Background(), mac)
	assert.Equal(t, domain.StateDisconnected, stored.ConnectionState, "Should update to Disconnected state")
	assert.Equal(t, "auth_failed", stored.ConnectionError, "Should set ConnectionError")
}

// TestDeviceRegistry_ConnectionStateTransitions verifies all state transitions
func TestDeviceRegistry_ConnectionStateTransitions(t *testing.T) {
	registry := NewDeviceRegistry(nil, nil)
	mac := "11:22:33:44:55:66"
	apMAC := "AA:BB:CC:DD:EE:FF"

	testCases := []struct {
		name           string
		state          domain.ConnectionState
		target         string
		error          string
		expectedState  domain.ConnectionState
		expectedTarget string
		expectedError  string
	}{
		{
			name:           "Initial Disconnected",
			state:          domain.StateDisconnected,
			target:         "",
			error:          "",
			expectedState:  domain.StateDisconnected,
			expectedTarget: "",
			expectedError:  "",
		},
		{
			name:           "Authenticating",
			state:          domain.StateAuthenticating,
			target:         apMAC,
			error:          "",
			expectedState:  domain.StateAuthenticating,
			expectedTarget: apMAC,
			expectedError:  "",
		},
		{
			name:           "Associating",
			state:          domain.StateAssociating,
			target:         apMAC,
			error:          "",
			expectedState:  domain.StateAssociating,
			expectedTarget: apMAC,
			expectedError:  "",
		},
		{
			name:           "Handshake",
			state:          domain.StateHandshake,
			target:         apMAC,
			error:          "",
			expectedState:  domain.StateHandshake,
			expectedTarget: apMAC,
			expectedError:  "",
		},
		{
			name:           "Connected",
			state:          domain.StateConnected,
			target:         apMAC,
			error:          "",
			expectedState:  domain.StateConnected,
			expectedTarget: apMAC,
			expectedError:  "",
		},
		{
			name:           "Auth Failed",
			state:          domain.StateDisconnected,
			target:         "",
			error:          "auth_failed",
			expectedState:  domain.StateDisconnected,
			expectedTarget: "",
			expectedError:  "auth_failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dev := domain.Device{
				MAC:              mac,
				Type:             "station",
				LastPacketTime:   time.Now(),
				ConnectionState:  tc.state,
				ConnectionTarget: tc.target,
				ConnectionError:  tc.error,
			}
			registry.ProcessDevice(context.Background(), dev)

			stored, found := registry.GetDevice(context.Background(), mac)
			assert.True(t, found)
			assert.Equal(t, tc.expectedState, stored.ConnectionState, "State mismatch in %s", tc.name)
			assert.Equal(t, tc.expectedTarget, stored.ConnectionTarget, "Target mismatch in %s", tc.name)
			assert.Equal(t, tc.expectedError, stored.ConnectionError, "Error mismatch in %s", tc.name)
		})
	}
}
