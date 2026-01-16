package sniffer

import (
	"context"
	"log"
	"math/rand"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/geo"
)

// MockSniffer generates fake/random devices to test the UI pipeline.
type MockSniffer struct {
	Output   chan<- domain.Device
	Location geo.Provider
}

// NewMock creates a new MockSniffer.
func NewMock(out chan<- domain.Device, loc geo.Provider) *MockSniffer {
	return &MockSniffer{
		Output:   out,
		Location: loc,
	}
}

// Scan simulates an active scan.
func (s *MockSniffer) Scan(target string) error {
	log.Printf("[MOCK] Active Scan requested for target: %s (simulated)", target)
	return nil
}

// Start starts the mock generation loop.
func (s *MockSniffer) Start(ctx context.Context) error {
	log.Println("Starting Mock Sniffer (generating fake traffic)...")

	// Fake MAC addresses
	macs := []string{
		"AA:BB:CC:DD:EE:01",
		"AA:BB:CC:DD:EE:02",
		"AA:BB:CC:DD:EE:03",
		"11:22:33:44:55:66",
		"CA:FE:BA:BE:00:00",
	}

	// Fake SSIDs
	ssids := []string{"Home_WiFi", "Free_Airport_WiFi", "Starbucks", "iPhone_Hotspot", ""}

	for {
		select {
		case <-ctx.Done():
			log.Println("Mock Sniffer stopping...")
			return nil
		default:
			// Continue
		}

		// Pick random device
		idx := rand.Intn(len(macs))
		mac := macs[idx]
		ssid := ssids[rand.Intn(len(ssids))]

		// Randomize RSSI
		rssi := -40 - rand.Intn(50) // -40 to -90

		// Get base location
		coords := s.Location.GetLocation()

		// Jitter location slightly to show movement on map (~10-20 meters)
		jitterLat := (rand.Float64() - 0.5) * 0.0005
		jitterLng := (rand.Float64() - 0.5) * 0.0005

		// Random type: Station or AP
		devType := "station"
		vendor := "Apple"
		if rand.Float32() < 0.2 {
			devType = "ap"
			vendor = "Cisco"
		}

		device := domain.Device{
			MAC:            mac,
			Type:           devType,
			Vendor:         vendor,
			RSSI:           rssi,
			SSID:           ssid,
			Latitude:       coords.Latitude + jitterLat,
			Longitude:      coords.Longitude + jitterLng,
			LastPacketTime: time.Now(),
			LastSeen:       time.Now(),
			ProbedSSIDs:    map[string]time.Time{ssid: time.Now()},
			Capabilities:   []string{"Mock-Cap"},
		}

		log.Printf("[MOCK] Detected Device: %s RSSI: %d SSID: %s", device.MAC, device.RSSI, device.SSID)
		s.Output <- device

		// Wait random interval or stop if context done
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(500+rand.Intn(1500)) * time.Millisecond):
			// continue
		}
	}
}

// SetChannels is a no-op for the mock sniffer.
func (s *MockSniffer) SetChannels(channels []int) {
	log.Printf("[MOCK] SetChannels called with: %v (no-op)", channels)
}

// GetChannels returns an empty list for the mock sniffer.
func (s *MockSniffer) GetChannels() []int {
	return []int{}
}

func (s *MockSniffer) SetInterfaceChannels(iface string, channels []int) {
	s.SetChannels(channels)
}

func (s *MockSniffer) GetInterfaceChannels(iface string) []int {
	return s.GetChannels()
}

func (s *MockSniffer) GetInterfaces() []string {
	return []string{"mock0"}
}

func (s *MockSniffer) GetInterfaceDetails() []domain.InterfaceInfo {
	return []domain.InterfaceInfo{{
		Name: "mock0",
		Capabilities: domain.InterfaceCapabilities{
			SupportedBands:    []string{"2.4ghz", "5ghz"},
			SupportedChannels: []int{1, 6, 11, 36, 40, 44, 48},
		},
		CurrentChannels: []int{1, 6, 11},
	}}
}

// Lock is a no-op for mock.
func (s *MockSniffer) Lock(iface string, channel int) error {
	log.Printf("[MOCK] Locking %s to channel %d", iface, channel)
	return nil
}

// Unlock is a no-op for mock.
func (s *MockSniffer) Unlock(iface string) error {
	log.Printf("[MOCK] Unlocking %s", iface)
	return nil
}

// ExecuteWithLock is a no-op wrapper for mock.
func (s *MockSniffer) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	return action()
}

// Close is a no-op for the mock sniffer.
func (s *MockSniffer) Close() {
	// No resources to release
}
