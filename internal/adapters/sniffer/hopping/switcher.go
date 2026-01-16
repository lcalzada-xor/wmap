package hopping

import (
	"fmt"
	"os/exec"
)

// ChannelSwitcher abstracts the mechanism for changing WiFi channels.
type ChannelSwitcher interface {
	SetChannel(iface string, channel int) error
}

// LinuxChannelSwitcher implements ChannelSwitcher using the 'iw' command.
type LinuxChannelSwitcher struct{}

// NewLinuxChannelSwitcher creates a new LinuxChannelSwitcher.
func NewLinuxChannelSwitcher() *LinuxChannelSwitcher {
	return &LinuxChannelSwitcher{}
}

// SetChannel executes the iw command to set the channel.
func (s *LinuxChannelSwitcher) SetChannel(iface string, channel int) error {
	cmd := exec.Command("iw", iface, "set", "channel", fmt.Sprintf("%d", channel))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set channel %d on %s: %w", channel, iface, err)
	}
	return nil
}
