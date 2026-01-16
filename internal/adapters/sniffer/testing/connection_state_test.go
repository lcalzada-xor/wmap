package sniffer

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllConnectionStatesReturned ensures that ALL connection states are properly returned
// by the packet handler. This test will FAIL if a new state is added but not included
// in the return condition.
func TestAllConnectionStatesReturned(t *testing.T) {
	mockLoc := ConnMockGeo{}
	handler := parser.NewPacketHandler(mockLoc, false, nil, nil)

	staMAC := "00:11:22:33:44:55"
	bssid := "aa:bb:cc:dd:ee:ff"

	// Define all expected states and their corresponding packet creators
	testCases := []struct {
		name          string
		expectedState string
		packetCreator func() gopacket.Packet
	}{
		{
			name:          "StateAuthenticating",
			expectedState: domain.StateAuthenticating,
			packetCreator: func() gopacket.Packet {
				return createAuthPacket(staMAC, bssid)
			},
		},
		{
			name:          "StateAssociating",
			expectedState: domain.StateAssociating,
			packetCreator: func() gopacket.Packet {
				return createAssocReqPacket(staMAC, bssid)
			},
		},
		{
			name:          "StateHandshake",
			expectedState: domain.StateHandshake,
			packetCreator: func() gopacket.Packet {
				return createEAPOLPacketConn(staMAC, bssid)
			},
		},
		{
			name:          "StateConnected",
			expectedState: domain.StateConnected,
			packetCreator: func() gopacket.Packet {
				return createDataPacket(staMAC, bssid, true)
			},
		},
		{
			name:          "StateDisconnected",
			expectedState: domain.StateDisconnected,
			packetCreator: func() gopacket.Packet {
				return createDeauthPacket(staMAC, bssid)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Wait for throttle window if testing Connected state
			if tc.expectedState == domain.StateConnected {
				time.Sleep(600 * time.Millisecond)
			}

			pkt := tc.packetCreator()
			dev, _ := handler.HandlePacket(pkt)

			// CRITICAL: Device must NOT be nil
			require.NotNil(t, dev, "Device is nil! State %s is not being returned by HandlePacket", tc.expectedState)

			// Verify the state matches (for non-EAPOL packets)
			if tc.expectedState != domain.StateHandshake {
				assert.Equal(t, tc.expectedState, dev.ConnectionState,
					"Expected state %s but got %s", tc.expectedState, dev.ConnectionState)
			}
		})
	}
}

// createAuthPacket creates an Authentication management frame
func createAuthPacket(staMAC, bssid string) gopacket.Packet {
	sta, _ := net.ParseMAC(staMAC)
	ap, _ := net.ParseMAC(bssid)

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtAuthentication,
		Address1: ap,  // DA (BSSID)
		Address2: sta, // SA (Client)
		Address3: ap,  // BSSID
	}

	auth := &layers.Dot11MgmtAuthentication{
		Algorithm: 0, // Open System
		Sequence:  1,
		Status:    0, // Success
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, dot11, auth)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeDot11, gopacket.Default)
}
