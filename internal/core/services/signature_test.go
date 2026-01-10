package services

import (
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

func setupSignatureTestService(sigStore ports.SignatureMatcher) *NetworkService {
	registry := NewDeviceRegistry(sigStore)
	security := NewSecurityEngine(registry)
	persistence := NewPersistenceManager(nil, 100)
	return NewNetworkService(registry, security, persistence, nil, nil)
}

func TestSignatureMatching(t *testing.T) {
	// Initial signatures for testing
	testSigs := []domain.DeviceSignature{
		{
			ID:         "sig_iphone",
			Model:      "iPhone (iOS 16+)",
			OS:         "iOS",
			IEPattern:  []int{0, 1, 50, 45, 127, 221, 221},
			Confidence: 0.9,
		},
	}
	sigMatcher := sniffer.NewSignatureStore(testSigs)
	svc := setupSignatureTestService(sigMatcher)

	// 1. Device with iPhone IE Pattern
	iphoneMAC := "00:17:F2:AA:BB:CC"
	svc.ProcessDevice(domain.Device{
		MAC:            iphoneMAC,
		Vendor:         "Apple",
		Type:           "station",
		IETags:         []int{0, 1, 50, 45, 127, 221, 221},
		LastPacketTime: time.Now(),
	})

	graph := svc.GetGraph()
	var node *domain.GraphNode
	for _, n := range graph.Nodes {
		if n.MAC == iphoneMAC {
			node = &n
			break
		}
	}

	if node == nil {
		t.Fatal("iPhone node not found")
	}

	if node.Model != "iPhone (iOS 16+)" {
		t.Errorf("Expected model iPhone (iOS 16+), got %s", node.Model)
	}
}

func TestOUISpoofingDetection(t *testing.T) {
	svc := setupSignatureTestService(nil)

	// Device claiming to be Apple but having generic/no IEs
	spoofedMAC := "00:17:F2:DE:AD:BE"
	svc.ProcessDevice(domain.Device{
		MAC:            spoofedMAC,
		Vendor:         "Apple", // Claims OUI
		Type:           "station",
		IETags:         []int{0, 1, 50, 3, 7, 8, 9, 10, 11}, // Many generic IEs, none matching Apple signature
		LastPacketTime: time.Now(),
	})

	alerts := svc.GetAlerts()
	found := false
	for _, alert := range alerts {
		if alert.DeviceMAC == spoofedMAC && alert.Subtype == "OUI_SPOOFING" {
			found = true
			break
		}
	}

	if !found {
		t.Error("OUI Spoofing alert not triggered for inconsistent device")
	}
}
