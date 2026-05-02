package monitor

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeviceMonitor handles querying HW capabilities and driver details.
type DeviceMonitor struct {
	iface        string
	capsCache    *domain.InterfaceCapabilities
	capsCacheMu  sync.RWMutex
	lastFetch    time.Time
}

func NewDeviceMonitor(iface string) *DeviceMonitor {
	return &DeviceMonitor{
		iface: iface,
	}
}

// GetMAC resolves the hardware MAC address of the interface.
func (m *DeviceMonitor) GetMAC() string {
	if iface, err := net.InterfaceByName(m.iface); err == nil {
		return iface.HardwareAddr.String()
	}
	return "Unknown"
}

// GetCapabilities fetches and caches the interface capabilities.
func (m *DeviceMonitor) GetCapabilities() *domain.InterfaceCapabilities {
	m.capsCacheMu.RLock()
	if m.capsCache != nil {
		caps := m.capsCache
		m.capsCacheMu.RUnlock()
		return caps
	}
	m.capsCacheMu.RUnlock()

	bandsMap, supportedChans, chanFreq, err := driver.GetInterfaceCapabilities(m.iface)
	if err != nil {
		log.Printf("Error getting capabilities for %s: %v", m.iface, err)
		return nil
	}

	driverName, _ := driver.GetDriverInfo(m.iface)
	mode, txPower, _ := driver.GetInterfaceCurrentConfig(m.iface)

	var bands []domain.WiFiBand
	for b := range bandsMap {
		bands = append(bands, domain.WiFiBand(b))
	}

	caps := &domain.InterfaceCapabilities{
		SupportedBands:    bands,
		SupportedChannels: supportedChans,
		ChannelFreq:       chanFreq,
		DriverName:        driverName,
		OperationMode:     domain.OperationMode(mode),
		TxPower:           txPower,
	}

	m.capsCacheMu.Lock()
	m.capsCache = caps
	m.lastFetch = time.Now()
	m.capsCacheMu.Unlock()

	return caps
}
