package registry

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRegistry for GraphBuilder tests
type MockRegistryGraph struct {
	mock.Mock
}

func (m *MockRegistryGraph) ProcessDevice(ctx context.Context, d domain.Device) (domain.Device, bool) {
	return d, false
}
func (m *MockRegistryGraph) LoadDevice(ctx context.Context, d domain.Device) {}
func (m *MockRegistryGraph) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	args := m.Called(mac)
	return args.Get(0).(domain.Device), args.Bool(1)
}
func (m *MockRegistryGraph) GetAllDevices(ctx context.Context) []domain.Device {
	args := m.Called()
	return args.Get(0).([]domain.Device)
}
func (m *MockRegistryGraph) GetSSIDs(ctx context.Context) map[string]bool {
	args := m.Called()
	return args.Get(0).(map[string]bool)
}
func (m *MockRegistryGraph) GetActiveCount(ctx context.Context) int                     { return 0 }
func (m *MockRegistryGraph) PruneOldDevices(ctx context.Context, ttl time.Duration) int { return 0 }
func (m *MockRegistryGraph) Clear(ctx context.Context)                                  {}
func (m *MockRegistryGraph) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	return "", false // Default stub
}
func (m *MockRegistryGraph) UpdateSSID(ctx context.Context, ssid, security string) {}
func (m *MockRegistryGraph) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	return 0
}

// Helpers for test stubs
func (m *MockRegistryGraph) Close() error { return nil }

func TestGraphBuilder_BuildGraph(t *testing.T) {
	mockReg := new(MockRegistryGraph)
	builder := NewGraphBuilder(mockReg)

	// Mock Data
	device1 := domain.Device{MAC: "00:11:22:33:44:55", Type: domain.DeviceTypeStation, Vendor: "Apple"}
	ap1 := domain.Device{MAC: "AA:BB:CC:DD:EE:FF", Type: domain.DeviceTypeAP, SSID: "MyWiFi", Vendor: "Cisco"}

	// Expectations
	mockReg.On("GetAllDevices").Return([]domain.Device{device1, ap1})
	mockReg.On("GetSSIDs").Return(map[string]bool{"MyWiFi": true})

	graph := builder.BuildGraph(context.Background())

	// Verify Nodes
	assert.Len(t, graph.Nodes, 3) // 2 devices + 1 SSID node

	var stationNode, apNode, ssidNode domain.GraphNode
	for _, n := range graph.Nodes {
		switch n.ID {
		case "dev_00:11:22:33:44:55":
			stationNode = n
		case "dev_AA:BB:CC:DD:EE:FF":
			apNode = n
		case "ssid_MyWiFi":
			ssidNode = n
		}
	}

	assert.Equal(t, domain.GroupStation, stationNode.Group)
	assert.Equal(t, domain.GroupAP, apNode.Group)
	assert.Equal(t, "MyWiFi", ssidNode.Label)
}

func TestGraphBuilder_Edges(t *testing.T) {
	mockReg := new(MockRegistryGraph)
	builder := NewGraphBuilder(mockReg)

	// Station connected to AP
	station := domain.Device{
		MAC:           "S1",
		ConnectedSSID: "A1", // MAC of AP
	}
	ap := domain.Device{
		MAC:  "A1",
		Type: domain.DeviceTypeAP,
		SSID: "CorpNet",
	}

	mockReg.On("GetAllDevices").Return([]domain.Device{station, ap})
	mockReg.On("GetSSIDs").Return(map[string]bool{"CorpNet": true})

	// IMPORTANT: BuildGraph calls GetDevice inside the loop for skipSSIDLink logic
	// if device.ConnectedSSID != ""
	mockReg.On("GetDevice", "A1").Return(ap, true)

	graph := builder.BuildGraph(context.Background())

	// Verify Edges
	// Should have:
	// 1. Connection edge S1 -> A1
	// 2. SSID edge A1 -> ssid_CorpNet (implied by AP having SSID)

	// Wait, code logic:
	// if device.SSID != "" -> link to ssid_SSID
	// AP has SSID="CorpNet", so A1 -> ssid_CorpNet
	// Station has no SSID field set in this test case used for association?
	// Usually station.ConnectedSSID is BSSID. The station might not know the SSID text if just probing?
	// But if connected, it usually implies SSID.
	// Let's assume station has SSID="CorpNet" too if associated.

	foundConnection := false
	for _, edge := range graph.Edges {
		if edge.From == "dev_S1" && edge.To == "dev_A1" {
			foundConnection = true
		}
	}
	assert.True(t, foundConnection, "Should have connection edge")
}
