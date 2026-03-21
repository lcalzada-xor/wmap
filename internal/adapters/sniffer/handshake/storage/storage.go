package storage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/session"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake/utils"
)

// Storage defines the interface for saving handshake captures.
type Storage interface {
	SaveSession(sess *session.HandshakeSession)
	SavePMKID(packet gopacket.Packet, bssid, essid string, beacon gopacket.Packet)
	GetFilePath(bssid, essid, stationMac string) string
}

// PcapStorage implements Storage by writing to .pcap files.
type PcapStorage struct {
	baseDir string
}

func NewPcapStorage(baseDir string) *PcapStorage {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		log.Printf("ERROR: Could not create handshake capture dir: %v", err)
	}
	return &PcapStorage{baseDir: baseDir}
}

func (s *PcapStorage) GetFilePath(bssid, essid, stationMac string) string {
	essidClean := utils.SanitizeFilename(essid)
	bssidClean := utils.SanitizeFilename(bssid)
	staClean := utils.SanitizeFilename(stationMac)

	filename := fmt.Sprintf("%s_%s_%s.pcap", bssidClean, essidClean, staClean)
	return filepath.Join(s.baseDir, filename)
}

func (s *PcapStorage) SaveSession(sess *session.HandshakeSession) {
	path := s.GetFilePath(sess.BSSID, sess.ESSID, sess.StationMAC)
	log.Printf("DEBUG: Attempting to save session to %s", path)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Error creating directory %s: %v", dir, err)
		return
	}

	f, err := os.Create(path)
	if err != nil {
		log.Printf("Error creating pcap file %s: %v", path, err)
		return
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	linkType := sess.LinkType
	if linkType == 0 {
		linkType = layers.LinkTypeIEEE80211Radio
	}
	w.WriteFileHeader(65536, linkType)

	allPackets := make([]gopacket.Packet, 0, len(sess.Frames)+1)
	if sess.Beacon != nil {
		allPackets = append(allPackets, sess.Beacon)
	}
	allPackets = append(allPackets, sess.Frames...)

	sort.Slice(allPackets, func(i, j int) bool {
		return allPackets[i].Metadata().Timestamp.Before(allPackets[j].Metadata().Timestamp)
	})

	for _, pkt := range allPackets {
		if err := w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
			log.Printf("Error writing packet to pcap: %v", err)
		}
	}
	log.Printf("DEBUG: Successfully saved session to %s (Packets: %d, LinkType: %d)", path, len(allPackets), linkType)
}

func (s *PcapStorage) SavePMKID(packet gopacket.Packet, bssid, essid string, beacon gopacket.Packet) {
	essidClean := utils.SanitizeFilename(essid)
	bssidClean := utils.SanitizeFilename(bssid)
	filename := fmt.Sprintf("%s_%s_PMKID.pcap", bssidClean, essidClean)
	path := filepath.Join(s.baseDir, filename)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Error creating directory %s: %v", dir, err)
		return
	}

	f, err := os.Create(path)
	if err != nil {
		log.Printf("Error creating PMKID pcap file %s: %v", path, err)
		return
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio)

	if beacon != nil {
		w.WritePacket(beacon.Metadata().CaptureInfo, beacon.Data())
	}

	w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	log.Printf("Saved PMKID capture: %s", filename)
}
