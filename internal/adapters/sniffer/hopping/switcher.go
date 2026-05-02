package hopping

import (
	"fmt"
	"os/exec"
)

// ChannelSwitcher abstracts the mechanism for changing WiFi channels.
type ChannelSwitcher interface {
	SetChannel(iface string, channel int) error
}

// vht80Groups maps each 5 GHz channel number to the center frequency (MHz) of
// its 80 MHz group. 802.11ac/ax groups four 20 MHz sub-channels; the center is
// always the midpoint of the group (primary + 30 MHz when primary is lowest).
// Monitor mode must tune to the center frequency with width 80 to receive all
// frames from clients using 80 MHz channels — tuning to the primary alone with
// no-HT/20 MHz misses most traffic.
var vht80Groups = map[int]int{
	// UNII-1 (5150–5250 MHz)
	36: 5210, 40: 5210, 44: 5210, 48: 5210,
	// UNII-2A (5250–5350 MHz)
	52: 5290, 56: 5290, 60: 5290, 64: 5290,
	// UNII-2C (5470–5725 MHz)
	100: 5530, 104: 5530, 108: 5530, 112: 5530,
	116: 5610, 120: 5610, 124: 5610, 128: 5610,
	132: 5690, 136: 5690, 140: 5690, 144: 5690,
	// UNII-3 (5725–5850 MHz)
	149: 5775, 153: 5775, 157: 5775, 161: 5775,
}

// LinuxChannelSwitcher implements ChannelSwitcher using the 'iw' command.
// For 5 GHz channels it uses "iw set freq <MHz> 80 <center1>" so that the
// adapter tunes to the full 80 MHz VHT/HE channel. This is required for DFS
// channels (where "iw set channel N" is rejected by the kernel) and ensures
// frames from 80 MHz clients are captured correctly.
type LinuxChannelSwitcher struct {
	// ChannelFreq maps channel number → primary frequency in MHz.
	// Populated from hardware capabilities at startup.
	ChannelFreq map[int]int
}

// NewLinuxChannelSwitcher creates a new LinuxChannelSwitcher.
func NewLinuxChannelSwitcher() *LinuxChannelSwitcher {
	return &LinuxChannelSwitcher{}
}

// SetChannel tunes iface to channel.
// For 5 GHz channels it issues "iw set freq <primary> 80 <center1>" to tune
// to the full 80 MHz group. If the channel is not in the VHT80 table (e.g.
// a standalone 160 MHz or an unlisted channel), it falls back to just the
// primary frequency without a width argument, which the kernel accepts in
// monitor mode. 2.4 GHz channels use the classic "iw set channel N".
func (s *LinuxChannelSwitcher) SetChannel(iface string, channel int) error {
	freq, hasFreq := s.ChannelFreq[channel]

	if hasFreq && channel >= 36 {
		args := []string{iface, "set", "freq", fmt.Sprintf("%d", freq)}
		if center1, ok := vht80Groups[channel]; ok {
			args = append(args, "80", fmt.Sprintf("%d", center1))
		}
		cmd := exec.Command("iw", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iw set freq %d on %s: %w (%s)", freq, iface, err, string(out))
		}
		return nil
	}

	cmd := exec.Command("iw", iface, "set", "channel", fmt.Sprintf("%d", channel))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iw set channel %d on %s: %w (%s)", channel, iface, err, string(out))
	}
	return nil
}
