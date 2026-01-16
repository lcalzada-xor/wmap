package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
	"github.com/lcalzada-xor/wmap/internal/core/services/registry"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockStorage implements ports.Storage for testing
type mockStorage struct {
	devices map[string]domain.Device
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		devices: make(map[string]domain.Device),
	}
}

func (m *mockStorage) SaveDevice(device domain.Device) error {
	m.devices[device.MAC] = device
	return nil
}

func (m *mockStorage) SaveDevicesBatch(devices []domain.Device) error {
	for _, d := range devices {
		m.devices[d.MAC] = d
	}
	return nil
}

func (m *mockStorage) GetDevice(mac string) (*domain.Device, error) {
	if d, ok := m.devices[mac]; ok {
		return &d, nil
	}
	return nil, nil // Return nil if not found for now
}

func (m *mockStorage) GetAllDevices() ([]domain.Device, error) {
	var list []domain.Device
	for _, d := range m.devices {
		list = append(list, d)
	}
	return list, nil
}

func (m *mockStorage) SaveProbe(mac string, ssid string) error {
	return nil
}

func (m *mockStorage) Close() error {
	return nil
}

// mockSniffer implements ports.Sniffer for testing
type mockSniffer struct{}

func (m *mockSniffer) Start(ctx context.Context) error { return nil }
func (m *mockSniffer) Scan(target string) error        { return nil }

func setupTestService() *NetworkService {
	reg := registry.NewDeviceRegistry(nil)
	sec := security.NewSecurityEngine(reg)
	// Passing nil storage to persistence for simple tests that check in-memory state
	persistence := persistence.NewPersistenceManager(nil, 100)
	return NewNetworkService(reg, sec, persistence, nil, nil)
}

func TestProcessDevice_NewDevice(t *testing.T) {
	svc := setupTestService()

	dev := domain.Device{
		MAC:            "00:11:22:33:44:55",
		RSSI:           -50,
		LastPacketTime: time.Now(),
		Vendor:         "TestVendor",
	}

	svc.ProcessDevice(dev)

	graph := svc.GetGraph()
	found := false
	for _, node := range graph.Nodes {
		if node.MAC == dev.MAC {
			found = true
			if node.RSSI != dev.RSSI {
				t.Errorf("Expected RSSI %d, got %d", dev.RSSI, node.RSSI)
			}
			if node.Vendor != "TestVendor" {
				t.Errorf("Expected Vendor TestVendor, got %s", node.Vendor)
			}
		}
	}
	if !found {
		t.Error("Device not found in graph after processing")
	}
}

func TestProcessDevice_UpdateDevice(t *testing.T) {
	svc := setupTestService()

	mac := "AA:BB:CC:DD:EE:FF"

	// 1st Packet
	svc.ProcessDevice(domain.Device{
		MAC:            mac,
		RSSI:           -80,
		PacketsCount:   1,
		LastPacketTime: time.Now(),
	})

	// 2nd Packet (Better RSSI, more packets)
	svc.ProcessDevice(domain.Device{
		MAC:            mac,
		RSSI:           -70,
		PacketsCount:   5,
		LastPacketTime: time.Now(),
	})

	graph := svc.GetGraph()
	var targetNode *domain.GraphNode
	for _, node := range graph.Nodes {
		if node.MAC == mac {
			val := node
			targetNode = &val
			break
		}
	}

	if targetNode == nil {
		t.Fatal("Node not found")
	}

	if targetNode.RSSI != -70 {
		t.Errorf("Expected latet RSSI -70, got %d", targetNode.RSSI)
	}
}

func TestProcessDevice_ConnectedAPPlaceholder(t *testing.T) {
	svc := setupTestService()

	stationMAC := "11:11:11:11:11:11"
	apMAC := "FF:FF:FF:FF:FF:FF"

	// Station connected to AP
	svc.ProcessDevice(domain.Device{
		MAC:            stationMAC,
		ConnectedSSID:  apMAC, // BSSID
		LastPacketTime: time.Now(),
	})

	graph := svc.GetGraph()

	// Should have 2 nodes: Station and Placeholder AP
	nodeCount := 0
	for _, node := range graph.Nodes {
		if node.MAC == stationMAC || node.MAC == apMAC {
			nodeCount++
		}
	}

	if nodeCount != 2 {
		t.Errorf("Expected 2 nodes (Station + AP), found %d interesting nodes", nodeCount)
	}

	// Check for Edge
	edgeFound := false
	for _, edge := range graph.Edges {
		if edge.From == "dev_"+stationMAC && edge.To == "dev_"+apMAC {
			edgeFound = true
			break
		}
	}
	if !edgeFound {
		t.Error("Edge between Station and AP not found")
	}
}

func TestProcessDevice_ProbedSSIDs(t *testing.T) {
	svc := setupTestService()

	mac := "CC:CC:CC:CC:CC:CC"
	probes := map[string]time.Time{
		"HomeWiFi": time.Now(),
		"FreeWiFi": time.Now(),
	}

	svc.ProcessDevice(domain.Device{
		MAC:            mac,
		ProbedSSIDs:    probes,
		LastPacketTime: time.Now(),
	})

	graph := svc.GetGraph()

	// Check if SSIDs exist as nodes
	ssidCount := 0
	for _, node := range graph.Nodes {
		if node.ID == "ssid_HomeWiFi" || node.ID == "ssid_FreeWiFi" {
			ssidCount++
		}
	}
	if ssidCount != 2 {
		t.Errorf("Expected 2 SSID nodes, found %d", ssidCount)
	}

	// Check edges
	edgeCount := 0
	for _, edge := range graph.Edges {
		if edge.From == "dev_"+mac && (edge.To == "ssid_HomeWiFi" || edge.To == "ssid_FreeWiFi") {
			if !edge.Dashed {
				t.Error("Probe edges should be dashed")
			}
			edgeCount++
		}
	}
	if edgeCount != 2 {
		t.Errorf("Expected 2 probe edges, found %d", edgeCount)
	}
}

func TestPruneOldDevices(t *testing.T) {
	svc := setupTestService()

	// Add Old Device
	oldMAC := "11:11:11:11:11:11"
	svc.ProcessDevice(domain.Device{
		MAC:            oldMAC,
		LastPacketTime: time.Now().Add(-20 * time.Minute),
	})

	// Add Active Device
	activeMAC := "22:22:22:22:22:22"
	svc.ProcessDevice(domain.Device{
		MAC:            activeMAC,
		LastPacketTime: time.Now().Add(-1 * time.Minute),
	})

	// Run Prune (TTL 10 mins) via registry
	svc.registry.PruneOldDevices(10 * time.Minute)

	graph := svc.GetGraph()
	foundOld := false
	foundActive := false

	for _, node := range graph.Nodes {
		if node.MAC == oldMAC {
			foundOld = true
		}
		if node.MAC == activeMAC {
			foundActive = true
		}
	}

	if foundOld {
		t.Error("Old device should have been pruned")
	}
	if !foundActive {
		t.Error("Active device should remain")
	}
}

func TestBehavioralProfiling(t *testing.T) {
	svc := setupTestService()

	mac := "BB:BB:BB:BB:BB:BB"
	now := time.Now()

	// 1. First Probe
	svc.ProcessDevice(domain.Device{
		MAC:            mac,
		Type:           "station",
		Capabilities:   []string{"Probe"},
		LastPacketTime: now,
	})

	// 2. Second Probe (10 seconds later)
	svc.ProcessDevice(domain.Device{
		MAC:            mac,
		Type:           "station",
		Capabilities:   []string{"Probe"},
		LastPacketTime: now.Add(10 * time.Second),
	})

	// 3. Third Probe (20 seconds after 2nd)
	svc.ProcessDevice(domain.Device{
		MAC:            mac,
		Type:           "station",
		Capabilities:   []string{"Probe"},
		LastPacketTime: now.Add(30 * time.Second),
	})

	output := svc.GetGraph()
	var node *domain.GraphNode
	for _, n := range output.Nodes {
		if n.MAC == mac {
			node = &n
			break
		}
	}

	if node == nil {
		t.Fatal("Node not found")
	}

	// Frequency should be roughly 15s (EMA of 10s and 20s)
	// Calculated as: (10 * 0.7 + 20 * 0.3) = 7 + 6 = 13s
	// Rounding to seconds: 13s
	if node.ProbeFrequency == "" {
		t.Error("Probe frequency should be populated")
	} else if node.ProbeFrequency != "13s" && node.ProbeFrequency != "14s" {
		t.Errorf("Expected ProbeFrequency around 13s, got %s", node.ProbeFrequency)
	}

	if len(node.ActiveHours) == 0 {
		t.Error("Active hours should be populated")
	}
}

// MockAuditService for testing
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) Log(ctx context.Context, action, target, details string) error {
	args := m.Called(ctx, action, target, details)
	return args.Error(0)
}

func (m *MockAuditService) GetLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

// MockDeauthService for testing
type MockDeauthService struct {
	mock.Mock
}

func (m *MockDeauthService) StartAttack(config domain.DeauthAttackConfig) (string, error) {
	args := m.Called(config)
	return args.String(0), args.Error(1)
}

func (m *MockDeauthService) StopAttack(id string, force bool) error {
	args := m.Called(id, force)
	return args.Error(0)
}

func (m *MockDeauthService) GetAttackStatus(id string) (domain.DeauthAttackStatus, error) {
	args := m.Called(id)
	return args.Get(0).(domain.DeauthAttackStatus), args.Error(1)
}

func (m *MockDeauthService) ListActiveAttacks() []domain.DeauthAttackStatus {
	args := m.Called()
	return args.Get(0).([]domain.DeauthAttackStatus)
}

func (m *MockDeauthService) SetLogger(logger func(string, string)) {
	m.Called(logger)
}

func (m *MockDeauthService) StopAll() {
	m.Called()
}

func TestStartDeauthAttack_AuditLog(t *testing.T) {
	reg := registry.NewDeviceRegistry(nil)
	sec := security.NewSecurityEngine(reg)
	persistence := persistence.NewPersistenceManager(nil, 100)

	mockAudit := new(MockAuditService)
	mockDeauth := new(MockDeauthService)

	svc := NewNetworkService(reg, sec, persistence, nil, mockAudit)
	svc.SetDeauthEngine(mockDeauth)

	// Setup Device in Registry for auto-channel
	reg.ProcessDevice(domain.Device{MAC: "TR:GT:00:00:00:01", Channel: 6})

	config := domain.DeauthAttackConfig{
		TargetMAC:  "TR:GT:00:00:00:01",
		AttackType: domain.DeauthBroadcast,
		Channel:    6,
	}

	// Expectations
	mockDeauth.On("StartAttack", config).Return("job-1", nil)

	// Use MatchedBy for details string
	mockAudit.On("Log", mock.Anything, domain.ActionDeauthStart, "TR:GT:00:00:00:01", mock.MatchedBy(func(details string) bool {
		return strings.Contains(details, "Ch: 6")
	})).Return(nil)

	// Execute
	id, err := svc.StartDeauthAttack(context.Background(), config)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, "job-1", id)
	mockAudit.AssertExpectations(t)
	mockDeauth.AssertExpectations(t)
}

func TestStartDeauthAttack_SmartTargeting(t *testing.T) {
	reg := registry.NewDeviceRegistry(nil)
	sec := security.NewSecurityEngine(reg)
	mockAudit := new(MockAuditService)
	svc := NewNetworkService(reg, sec, nil, nil, mockAudit)
	mockDeauth := new(MockDeauthService)
	svc.SetDeauthEngine(mockDeauth)

	// 1. Setup Registry with AP and Client
	apMAC := "AA:BB:CC:DD:EE:FF"
	clientMAC := "11:22:33:44:55:66"

	reg.ProcessDevice(domain.Device{MAC: apMAC, Type: "ap", Channel: 6})
	reg.ProcessDevice(domain.Device{
		MAC:            clientMAC,
		Type:           "station",
		ConnectedSSID:  apMAC,
		LastPacketTime: time.Now(), // Recently active
	})

	// 2. Request Broadcast Attack
	config := domain.DeauthAttackConfig{
		TargetMAC:  apMAC,
		AttackType: domain.DeauthBroadcast,
		Channel:    6,
	}

	// 3. Expect UPGRADED Attack
	// Expect Smart Targeting Log
	mockAudit.On("Log", mock.Anything, domain.ActionInfo, apMAC, mock.MatchedBy(func(details string) bool {
		return strings.Contains(details, "Upgraded Broadcast -> Targeted")
	})).Return(nil)

	// Expect Start Log
	mockAudit.On("Log", mock.Anything, domain.ActionDeauthStart, apMAC, mock.Anything).Return(nil)

	mockDeauth.On("StartAttack", mock.MatchedBy(func(c domain.DeauthAttackConfig) bool {
		return c.AttackType == domain.DeauthTargeted && c.ClientMAC == clientMAC
	})).Return("job-smart", nil)

	// Execute
	id, err := svc.StartDeauthAttack(context.Background(), config)

	assert.NoError(t, err)
	assert.Equal(t, "job-smart", id)
	mockDeauth.AssertExpectations(t)
}

func TestStartDeauthAttack_AutoChannels(t *testing.T) {
	reg := registry.NewDeviceRegistry(nil)
	sec := security.NewSecurityEngine(reg)
	mockAudit := new(MockAuditService)
	svc := NewNetworkService(reg, sec, nil, nil, mockAudit)
	mockDeauth := new(MockDeauthService)
	svc.SetDeauthEngine(mockDeauth)

	// Setup: Device exists in registry with Channel 11
	targetMAC := "11:22:33:44:55:66"
	reg.ProcessDevice(domain.Device{MAC: targetMAC, Channel: 11})

	// Config with Channel 0 (Auto)
	config := domain.DeauthAttackConfig{
		TargetMAC:  targetMAC,
		AttackType: domain.DeauthBroadcast,
		Channel:    0,
	}

	// Expect StartAttack with Channel 11 detected
	mockDeauth.On("StartAttack", mock.MatchedBy(func(c domain.DeauthAttackConfig) bool {
		return c.Channel == 11
	})).Return("job-auto", nil)

	mockAudit.On("Log", mock.Anything, domain.ActionDeauthStart, targetMAC, mock.MatchedBy(func(details string) bool {
		return strings.Contains(details, "Ch: 11")
	})).Return(nil)

	// Execute
	// Execute
	id, err := svc.StartDeauthAttack(context.Background(), config)

	assert.NoError(t, err)
	assert.Equal(t, "job-auto", id)
	mockDeauth.AssertExpectations(t)
}
