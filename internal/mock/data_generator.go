package mock

import (
	"fmt"
	"math/rand"
	"time"
)

// Common SSIDs for realistic mock data
var commonSSIDs = []string{
	"HomeNetwork", "NETGEAR-5G", "Starbucks WiFi", "TP-Link_2.4GHz",
	"Linksys", "ATT-WiFi", "Xfinity", "Google Fiber",
	"Office-Network", "Guest-WiFi", "MyWiFi", "Home-2.4G",
	"DIRECT-Printer", "AndroidAP", "iPhone", "Samsung Galaxy",
	"CoffeeShop_Free", "Airport_WiFi", "Hotel-Guest", "Apartment_5G",
}

// Vendor OUI prefixes (first 3 bytes of MAC)
var vendorPrefixes = map[string]string{
	"Apple":    "00:17:F2",
	"Samsung":  "00:12:FB",
	"Cisco":    "00:1E:BD",
	"TP-Link":  "50:C7:BF",
	"Netgear":  "A0:63:91",
	"Linksys":  "00:14:BF",
	"Google":   "F4:F5:D8",
	"Amazon":   "FC:A6:67",
	"Xiaomi":   "34:CE:00",
	"Huawei":   "00:E0:FC",
	"Intel":    "00:13:02",
	"Broadcom": "00:10:18",
	"Qualcomm": "00:03:7F",
	"Asus":     "00:1F:C6",
	"D-Link":   "00:17:9A",
	"Belkin":   "00:11:50",
	"Motorola": "00:04:56",
	"Nokia":    "00:1E:3A",
	"Sony":     "00:13:A9",
	"LG":       "00:1C:62",
}

// Device names for stations
var deviceNames = []string{
	"iPhone 13", "iPhone 14 Pro", "iPhone 12", "iPhone SE",
	"Samsung Galaxy S21", "Samsung Galaxy S22", "Samsung Note 20",
	"Google Pixel 6", "Google Pixel 7", "OnePlus 9",
	"MacBook Pro", "MacBook Air", "iPad Pro", "iPad Air",
	"Dell XPS 13", "ThinkPad X1", "HP Spectre", "Surface Laptop",
	"Amazon Echo", "Google Home", "Nest Hub", "Ring Doorbell",
	"PlayStation 5", "Xbox Series X", "Nintendo Switch",
	"Smart TV", "Roku", "Chromecast", "Apple TV",
}

// Security types
var securityTypes = []string{"WPA2", "WPA3", "WEP", "OPEN"}

// Channels for 2.4GHz and 5GHz
var channels24GHz = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
var channels5GHz = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}

// MockDevice represents a mock WiFi device
type MockDevice struct {
	MAC          string
	Type         string // "AP" or "STA"
	SSID         string
	Channel      int
	Security     string
	RSSI         int
	Vendor       string
	WPS          bool
	Hidden       bool
	Frequency    string // "2.4GHz" or "5GHz"
	DeviceName   string // For stations
	Connected    bool   // For stations
	ConnectedTo  string // MAC of AP (for stations)
	LastSeen     time.Time
	PacketCount  int
	HasHandshake bool
}

// DataGenerator generates mock WiFi data
type DataGenerator struct {
	rand     *rand.Rand
	devices  map[string]*MockDevice
	aps      []*MockDevice
	stations []*MockDevice
}

// NewDataGenerator creates a new mock data generator
func NewDataGenerator() *DataGenerator {
	return &DataGenerator{
		rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
		devices:  make(map[string]*MockDevice),
		aps:      make([]*MockDevice, 0),
		stations: make([]*MockDevice, 0),
	}
}

// GenerateMAC generates a random MAC address with optional vendor prefix
func (g *DataGenerator) GenerateMAC(vendor string) string {
	prefix := ""
	if vendor != "" {
		if p, ok := vendorPrefixes[vendor]; ok {
			prefix = p
		}
	}

	if prefix == "" {
		// Random vendor
		vendors := make([]string, 0, len(vendorPrefixes))
		for v := range vendorPrefixes {
			vendors = append(vendors, v)
		}
		vendor = vendors[g.rand.Intn(len(vendors))]
		prefix = vendorPrefixes[vendor]
	}

	// Generate last 3 bytes
	suffix := fmt.Sprintf("%02X:%02X:%02X",
		g.rand.Intn(256),
		g.rand.Intn(256),
		g.rand.Intn(256))

	return prefix + ":" + suffix
}

// GenerateAP creates a mock Access Point
func (g *DataGenerator) GenerateAP() *MockDevice {
	vendor := g.randomVendor()
	ssid := commonSSIDs[g.rand.Intn(len(commonSSIDs))]

	// Determine frequency
	is5GHz := g.rand.Float32() < 0.4 // 40% chance of 5GHz
	var channel int
	var frequency string

	if is5GHz {
		channel = channels5GHz[g.rand.Intn(len(channels5GHz))]
		frequency = "5GHz"
	} else {
		channel = channels24GHz[g.rand.Intn(len(channels24GHz))]
		frequency = "2.4GHz"
	}

	// Security (weighted towards WPA2)
	securityWeights := []float32{0.6, 0.2, 0.05, 0.15} // WPA2, WPA3, WEP, OPEN
	security := g.weightedChoice(securityTypes, securityWeights)

	ap := &MockDevice{
		MAC:          g.GenerateMAC(vendor),
		Type:         "AP",
		SSID:         ssid,
		Channel:      channel,
		Security:     security,
		RSSI:         -30 - g.rand.Intn(40), // -30 to -70 dBm
		Vendor:       vendor,
		WPS:          g.rand.Float32() < 0.3, // 30% have WPS
		Hidden:       g.rand.Float32() < 0.1, // 10% hidden
		Frequency:    frequency,
		LastSeen:     time.Now(),
		PacketCount:  g.rand.Intn(1000) + 100,
		HasHandshake: false,
	}

	g.devices[ap.MAC] = ap
	g.aps = append(g.aps, ap)
	return ap
}

// GenerateStation creates a mock Station
func (g *DataGenerator) GenerateStation(connectToAP *MockDevice) *MockDevice {
	vendor := g.randomVendor()
	deviceName := deviceNames[g.rand.Intn(len(deviceNames))]

	sta := &MockDevice{
		MAC:         g.GenerateMAC(vendor),
		Type:        "STA",
		RSSI:        -40 - g.rand.Intn(50), // -40 to -90 dBm
		Vendor:      vendor,
		DeviceName:  deviceName,
		Connected:   connectToAP != nil,
		LastSeen:    time.Now(),
		PacketCount: g.rand.Intn(500) + 50,
	}

	if connectToAP != nil {
		sta.ConnectedTo = connectToAP.MAC
		sta.SSID = connectToAP.SSID
		sta.Channel = connectToAP.Channel
		sta.Frequency = connectToAP.Frequency
	}

	g.devices[sta.MAC] = sta
	g.stations = append(g.stations, sta)
	return sta
}

// GenerateScenario creates a complete mock scenario
func (g *DataGenerator) GenerateScenario(scenario string) {
	var numAPs, numStations int

	switch scenario {
	case "basic":
		numAPs = 5
		numStations = 10
	case "crowded":
		numAPs = 20
		numStations = 50
	case "attack":
		numAPs = 8
		numStations = 15
	case "vulnerable":
		numAPs = 10
		numStations = 20
	default:
		numAPs = 5
		numStations = 10
	}

	// Generate APs
	for i := 0; i < numAPs; i++ {
		g.GenerateAP()
	}

	// Generate Stations (80% connected, 20% probing)
	for i := 0; i < numStations; i++ {
		var ap *MockDevice
		if g.rand.Float32() < 0.8 && len(g.aps) > 0 {
			ap = g.aps[g.rand.Intn(len(g.aps))]
		}
		g.GenerateStation(ap)
	}

	// For vulnerable scenario, mark some APs
	if scenario == "vulnerable" {
		for _, ap := range g.aps {
			if ap.Security == "WEP" || ap.WPS {
				// Already vulnerable
			}
		}
	}

	// For attack scenario, simulate some handshakes
	if scenario == "attack" {
		for i := 0; i < 3 && i < len(g.aps); i++ {
			g.aps[i].HasHandshake = true
		}
	}
}

// GetDevices returns all devices
func (g *DataGenerator) GetDevices() []*MockDevice {
	devices := make([]*MockDevice, 0, len(g.devices))
	for _, d := range g.devices {
		devices = append(devices, d)
	}
	return devices
}

// GetAPs returns all APs
func (g *DataGenerator) GetAPs() []*MockDevice {
	return g.aps
}

// GetStations returns all stations
func (g *DataGenerator) GetStations() []*MockDevice {
	return g.stations
}

// Helper functions

func (g *DataGenerator) randomVendor() string {
	vendors := make([]string, 0, len(vendorPrefixes))
	for v := range vendorPrefixes {
		vendors = append(vendors, v)
	}
	return vendors[g.rand.Intn(len(vendors))]
}

func (g *DataGenerator) weightedChoice(choices []string, weights []float32) string {
	total := float32(0)
	for _, w := range weights {
		total += w
	}

	r := g.rand.Float32() * total
	cumulative := float32(0)

	for i, w := range weights {
		cumulative += w
		if r <= cumulative {
			return choices[i]
		}
	}

	return choices[0]
}

// SimulateActivity simulates network activity (devices appearing/disappearing)
func (g *DataGenerator) SimulateActivity() {
	// 10% chance to add a new device
	if g.rand.Float32() < 0.1 {
		if g.rand.Float32() < 0.3 {
			// Add new AP
			g.GenerateAP()
		} else {
			// Add new station
			var ap *MockDevice
			if len(g.aps) > 0 && g.rand.Float32() < 0.7 {
				ap = g.aps[g.rand.Intn(len(g.aps))]
			}
			g.GenerateStation(ap)
		}
	}

	// 5% chance to remove a device
	if g.rand.Float32() < 0.05 && len(g.devices) > 5 {
		// Remove random device
		devices := g.GetDevices()
		if len(devices) > 0 {
			toRemove := devices[g.rand.Intn(len(devices))]
			delete(g.devices, toRemove.MAC)

			// Remove from aps/stations lists
			if toRemove.Type == "AP" {
				for i, ap := range g.aps {
					if ap.MAC == toRemove.MAC {
						g.aps = append(g.aps[:i], g.aps[i+1:]...)
						break
					}
				}
			} else {
				for i, sta := range g.stations {
					if sta.MAC == toRemove.MAC {
						g.stations = append(g.stations[:i], g.stations[i+1:]...)
						break
					}
				}
			}
		}
	}

	// Update RSSI for all devices (simulate movement)
	for _, device := range g.devices {
		delta := g.rand.Intn(10) - 5 // -5 to +5 dBm
		device.RSSI += delta
		if device.RSSI > -20 {
			device.RSSI = -20
		}
		if device.RSSI < -95 {
			device.RSSI = -95
		}
		device.LastSeen = time.Now()
		device.PacketCount += g.rand.Intn(50)
	}
}
