package security

import (
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// BehaviorEngine handles behavioral analysis and profiling of devices.
type BehaviorEngine struct{}

// NewBehaviorEngine creates a new BehaviorEngine.
func NewBehaviorEngine() *BehaviorEngine {
	return &BehaviorEngine{}
}

// UpdateProfile updates the behavioral profile with new device interactions.
func (e *BehaviorEngine) UpdateProfile(profile domain.BehavioralProfile, device domain.Device) domain.BehavioralProfile {
	// Initialize if empty
	if profile.MAC == "" {
		profile.MAC = device.MAC
		profile.ActiveHours = make([]int, 0)
		profile.LastUpdated = time.Now()
	}

	if device.Type == "station" || device.Type == "" {
		hour := device.LastPacketTime.Hour()
		exists := false
		for _, h := range profile.ActiveHours {
			if h == hour {
				exists = true
				break
			}
		}
		if !exists {
			profile.ActiveHours = append(profile.ActiveHours, hour)
		}

		isProbe := false
		for _, cap := range device.Capabilities {
			if cap == "Probe" {
				isProbe = true
				break
			}
		}

		if isProbe {
			if !profile.LastProbeTime.IsZero() {
				interval := device.LastPacketTime.Sub(profile.LastProbeTime)
				if interval > 0 {
					if profile.ProbeFrequency == 0 {
						profile.ProbeFrequency = interval
					} else {
						profile.ProbeFrequency = time.Duration(float64(profile.ProbeFrequency)*0.7 + float64(interval)*0.3)
					}
				}
			}
			profile.LastProbeTime = device.LastPacketTime
		}
	}

	profile.UniqueSSIDs = len(device.ProbedSSIDs)
	profile.SSIDSignature = e.GenerateSSIDSignature(device.ProbedSSIDs)
	if len(device.IETags) > 0 {
		profile.IETags = device.IETags
	}
	profile.LastUpdated = time.Now()

	return profile
}

// GenerateSSIDSignature creates a comma-separated sorted list of SSIDs.
func (e *BehaviorEngine) GenerateSSIDSignature(probes map[string]time.Time) string {
	if len(probes) == 0 {
		return ""
	}
	ssids := make([]string, 0, len(probes))
	for s := range probes {
		ssids = append(ssids, s)
	}
	sort.Strings(ssids)
	return strings.Join(ssids, ",")
}

// CalculateMatchScore computes the similarity score between a profile and a new device.
func (e *BehaviorEngine) CalculateMatchScore(profile domain.BehavioralProfile, newDevice domain.Device) float64 {
	// Check for randomized MAC on newDevice should be done before calling this?
	// Or we assume this is called for randomized devices.

	newSig := e.GenerateSSIDSignature(newDevice.ProbedSSIDs)
	if newSig == "" {
		return 0
	}

	if profile.SSIDSignature == "" {
		return 0
	}

	// Score based on SSID signature similarity
	score := 0.0
	if profile.SSIDSignature == newSig {
		score = 0.8
	} else if strings.Contains(profile.SSIDSignature, newSig) || strings.Contains(newSig, profile.SSIDSignature) {
		score = 0.4
	}

	// Add IE tag similarity if available
	if len(profile.IETags) > 0 && len(newDevice.IETags) > 0 {
		ieMatch := 0
		minLen := len(profile.IETags)
		if len(newDevice.IETags) < minLen {
			minLen = len(newDevice.IETags)
		}
		for i := 0; i < minLen; i++ {
			if profile.IETags[i] == newDevice.IETags[i] {
				ieMatch++
			}
		}
		ieScore := float64(ieMatch) / float64(minLen)
		score = (score * 0.6) + (ieScore * 0.4)
	}

	return score
}

// IsRandomizedMAC checks if the MAC address is locally administered.
func (e *BehaviorEngine) IsRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	// "xx:..." -> firstByte is mac[0:2]
	// But mac string has colons? Usually standard format.
	// If standard format with colons: "00:..."
	cleanMac := strings.ReplaceAll(mac, ":", "")
	if len(cleanMac) < 2 {
		return false
	}
	firstByte, err := hex.DecodeString(cleanMac[0:2])
	if err != nil || len(firstByte) == 0 {
		return false
	}
	// 0x02 bit set means locally administered
	return (firstByte[0] & 0x02) != 0
}
