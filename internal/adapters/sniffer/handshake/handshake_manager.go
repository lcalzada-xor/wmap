package handshake

import (
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/cache"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/session"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/storage"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/utils"
)

const (
	defaultSessionTimeout    = 5 * time.Minute
	incompleteSessionTimeout = 60 * time.Second
	cleanupInterval          = 1 * time.Minute
	maxFramesPerSession      = 20
)

// HandshakeManager handles the capture and storage of WPA/WPA2 handshakes.
type HandshakeManager struct {
	mu        sync.RWMutex
	cache     *cache.NetworkCache
	storage   storage.Storage
	sessions  map[string]*session.HandshakeSession
	saveQueue chan *session.HandshakeSession
	stopChan  chan struct{}
}

// NewHandshakeManager creates a new manager.
func NewHandshakeManager(baseDir string) *HandshakeManager {
	hm := &HandshakeManager{
		cache:     cache.NewNetworkCache(),
		storage:   storage.NewPcapStorage(baseDir),
		sessions:  make(map[string]*session.HandshakeSession),
		saveQueue: make(chan *session.HandshakeSession, 500),
		stopChan:  make(chan struct{}),
	}

	go hm.startCleanupRoutine()
	go hm.saveLoop()

	return hm
}

// Close stops background routines.
func (hm *HandshakeManager) Close() {
	close(hm.stopChan)
}

func (hm *HandshakeManager) startCleanupRoutine() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[HANDSHAKE-MANAGER] Panic in cleanup routine: %v", r)
		}
	}()
	for {
		select {
		case <-ticker.C:
			hm.CleanupSessions()
		case <-hm.stopChan:
			return
		}
	}
}

func (hm *HandshakeManager) saveLoop() {
	for {
		select {
		case sess := <-hm.saveQueue:
			hm.storage.SaveSession(sess)
		case <-hm.stopChan:
			return
		}
	}
}

// CleanupSessions removes sessions that haven't been updated recently.
func (hm *HandshakeManager) CleanupSessions() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	now := time.Now()
	for key, sess := range hm.sessions {
		timeout := defaultSessionTimeout
		if !sess.IsComplete() {
			timeout = incompleteSessionTimeout
		}

		if now.Sub(sess.LastUpdate) > timeout {
			delete(hm.sessions, key)
		}
	}
}

// ProcessFrame inspects packets for Beacons (to map BSSID->ESSID) and EAPOL frames.
// Returns true if a handshake file was saved/updated.
func (hm *HandshakeManager) ProcessFrame(packet gopacket.Packet) bool {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return false
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return false
	}

	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		bssid := dot11.Address3.String()
		if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
			essid := utils.GetSSIDFromPacket(packet)
			if essid != "" && essid != "<HIDDEN>" {
				hm.cache.StoreBeacon(bssid, essid, packet)

				hm.mu.Lock()
				for _, sess := range hm.sessions {
					if sess.BSSID == bssid {
						if sess.Beacon == nil {
							sess.Beacon = packet
							sess.ESSID = essid
							if sess.LinkType == 0 {
								sess.LinkType = utils.DetectLinkType(packet)
							}
						}
					}
				}
				hm.mu.Unlock()
			}
		}
		return false
	}

	isKey := utils.IsEAPOLKey(packet)
	isWPS := utils.IsWPSFrame(packet)

	if isKey || isWPS {
		return hm.handleEAPOL(packet, dot11, isWPS)
	}

	if dot11.Type == layers.Dot11TypeMgmtAuthentication ||
		dot11.Type == layers.Dot11TypeMgmtAssociationReq ||
		dot11.Type == layers.Dot11TypeMgmtReassociationReq {
		return hm.handleManagementFrame(packet, dot11)
	}

	return false
}

func (hm *HandshakeManager) handleManagementFrame(packet gopacket.Packet, dot11 *layers.Dot11) bool {
	var bssid, stationMac string
	if dot11.Type == layers.Dot11TypeMgmtAuthentication {
		bssid = dot11.Address3.String()
		if dot11.Address2.String() == bssid {
			stationMac = dot11.Address1.String()
		} else {
			stationMac = dot11.Address2.String()
		}
	} else {
		bssid = dot11.Address1.String()
		stationMac = dot11.Address2.String()
	}

	key := bssid + "_" + stationMac

	hm.mu.Lock()
	defer hm.mu.Unlock()

	sess, exists := hm.sessions[key]
	if !exists {
		essid := hm.cache.GetESSID(bssid)
		beacon := hm.cache.GetBeacon(bssid)
		sess = session.NewHandshakeSession(bssid, stationMac, essid, beacon, utils.DetectLinkType(packet))
		hm.sessions[key] = sess
	} else if sess.LinkType == 0 {
		sess.LinkType = utils.DetectLinkType(packet)
	}

	sess.AppendFrame(packet, maxFramesPerSession)
	return false
}

func (hm *HandshakeManager) handleEAPOL(packet gopacket.Packet, dot11 *layers.Dot11, isWPS bool) bool {
	var bssid, stationMac string
	toDS := dot11.Flags.ToDS()
	fromDS := dot11.Flags.FromDS()

	if !toDS && !fromDS {
		bssid = dot11.Address3.String()
		if dot11.Address2.String() == bssid {
			stationMac = dot11.Address1.String()
		} else {
			stationMac = dot11.Address2.String()
		}
	} else if !toDS && fromDS {
		bssid = dot11.Address2.String()
		stationMac = dot11.Address1.String()
	} else if toDS && !fromDS {
		bssid = dot11.Address1.String()
		stationMac = dot11.Address2.String()
	} else {
		return false
	}

	key := bssid + "_" + stationMac

	hm.mu.Lock()
	defer hm.mu.Unlock()

	sess, exists := hm.sessions[key]
	if !exists {
		essid := hm.cache.GetESSID(bssid)
		beacon := hm.cache.GetBeacon(bssid)
		sess = session.NewHandshakeSession(bssid, stationMac, essid, beacon, utils.DetectLinkType(packet))
		hm.sessions[key] = sess
	}

	sess.UpdateESSID(hm.cache.GetESSID(bssid))
	wasAppended, isDuplicate := sess.AppendFrame(packet, maxFramesPerSession)

	shouldSave := false
	if !isDuplicate || isWPS {
		shouldSave = sess.ProcessEAPOL(packet, isWPS, wasAppended)
	}

	if shouldSave && sess.ShouldTriggerSave() {
		sessionCopy := sess.Clone()
		sess.SavedCount = len(sess.Frames)
		select {
		case hm.saveQueue <- sessionCopy:
		default:
			log.Printf("Warning: Handshake save queue full")
		}
		return true
	}

	return false
}

// RegisterNetwork manually registers an ESSID for a BSSID
func (hm *HandshakeManager) RegisterNetwork(bssid, essid string) {
	hm.cache.RegisterNetwork(bssid, essid)
}

// SavePMKID saves a single packet containing a PMKID to a pcap file.
func (hm *HandshakeManager) SavePMKID(packet gopacket.Packet, bssid, essid string) {
	if essid == "" {
		essid = hm.cache.GetESSID(bssid)
	}
	beacon := hm.cache.GetBeacon(bssid)
	hm.storage.SavePMKID(packet, bssid, essid, beacon)
}

// HasHandshake returns true if a handshake has been captured for the given BSSID.
func (hm *HandshakeManager) HasHandshake(bssid string) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	for _, sess := range hm.sessions {
		if sess.BSSID == bssid && sess.Captured[2] && (sess.Captured[1] || sess.Captured[3]) {
			return true
		}
	}
	return false
}

// GetHandshakeFile returns the path to the captured handshake file for a given BSSID.
func (hm *HandshakeManager) GetHandshakeFile(bssid string) string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var bestSession *session.HandshakeSession
	for _, sess := range hm.sessions {
		if sess.BSSID == bssid && sess.Captured[2] && (sess.Captured[1] || sess.Captured[3]) {
			if bestSession == nil || sess.LastUpdate.After(bestSession.LastUpdate) {
				bestSession = sess
			}
		}
	}

	if bestSession != nil {
		return hm.storage.GetFilePath(bestSession.BSSID, bestSession.ESSID, bestSession.StationMAC)
	}
	return ""
}
