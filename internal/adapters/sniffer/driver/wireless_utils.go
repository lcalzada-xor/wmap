package driver

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CommandExecutor abstracts system command execution
type CommandExecutor interface {
	Execute(name string, args ...string) ([]byte, error)
}

// SystemCommandExecutor implements CommandExecutor using os/exec
type SystemCommandExecutor struct{}

func (e *SystemCommandExecutor) Execute(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// WirelessDriver handles interaction with wireless interfaces
type WirelessDriver struct {
	executor CommandExecutor
}

// DefaultDriver is the default instance using system commands
var DefaultDriver = &WirelessDriver{executor: &SystemCommandExecutor{}}

// SetExecutor允许 for testing
func SetExecutor(e CommandExecutor) {
	DefaultDriver.executor = e
}

// HardwareCapabilities defines what a WiFi card supports.
type HardwareCapabilities struct {
	Supported frequencies
}

type frequencies struct {
	Bands map[string][]int
}

// GetInterfaceCapabilities returns the supported channels for a given interface.
func GetInterfaceCapabilities(iface string) (map[string]bool, []int, error) {
	return DefaultDriver.GetInterfaceCapabilities(iface)
}

func (d *WirelessDriver) GetInterfaceCapabilities(iface string) (map[string]bool, []int, error) {
	// 1. Map Interface -> Phy
	phy, err := d.getPhyForInterface(iface)
	if err != nil {
		return nil, nil, err
	}

	// 2. Get Phy Capabilities
	return d.getPhyCapabilities(phy)
}

func (d *WirelessDriver) getPhyForInterface(iface string) (string, error) {
	out, err := d.executor.Execute("iw", "dev")
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	currentPhy := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "phy#") {
			currentPhy = line
		} else if strings.HasPrefix(line, "Interface "+iface) {
			return strings.Replace(currentPhy, "#", "", 1), nil
		}
	}
	return "", fmt.Errorf("interface %s not found in iw dev output", iface)
}

func (d *WirelessDriver) getPhyCapabilities(phy string) (map[string]bool, []int, error) {
	out, err := d.executor.Execute("iw", "phy", phy, "info")
	if err != nil {
		return nil, nil, err
	}

	bands := make(map[string]bool)
	supportedChannels := []int{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inFrequencies := false
	reChannel := regexp.MustCompile(`\[([0-9]+)\]`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "Frequencies:" {
			inFrequencies = true
			continue
		}

		if inFrequencies {
			if strings.HasPrefix(line, "*") {
				if strings.Contains(line, "(disabled)") || strings.Contains(line, "(no IR)") {
					if strings.Contains(line, "(disabled)") {
						continue
					}
				}

				matches := reChannel.FindStringSubmatch(line)
				if len(matches) > 1 {
					ch, _ := strconv.Atoi(matches[1])
					supportedChannels = append(supportedChannels, ch)

					if ch >= 1 && ch <= 14 {
						bands["2.4ghz"] = true
					} else if ch >= 36 {
						bands["5ghz"] = true
					}
				}
			} else if !strings.HasPrefix(line, "*") {
				inFrequencies = false
			}
		}
	}

	return bands, supportedChannels, nil
}

// SetInterfaceChannel sets the WiFi channel for a given interface.
func SetInterfaceChannel(iface string, channel int) error {
	return DefaultDriver.SetInterfaceChannel(iface, channel)
}

func (d *WirelessDriver) SetInterfaceChannel(iface string, channel int) error {
	if channel <= 0 {
		return fmt.Errorf("invalid channel: %d", channel)
	}
	output, err := d.executor.Execute("iw", iface, "set", "channel", fmt.Sprintf("%d", channel))
	if err != nil {
		return fmt.Errorf("failed to set channel %d on %s: %v (%s)", channel, iface, err, string(output))
	}
	return nil
}

// SetInterfaceChannelWithRetry sets the WiFi channel with retry logic
func SetInterfaceChannelWithRetry(iface string, channel int, maxRetries int) error {
	return DefaultDriver.SetInterfaceChannelWithRetry(iface, channel, maxRetries)
}

func (d *WirelessDriver) SetInterfaceChannelWithRetry(iface string, channel int, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := d.SetInterfaceChannel(iface, channel); err == nil {
			return nil
		} else {
			lastErr = err
			time.Sleep(time.Millisecond * 100 * time.Duration(i+1))
		}
	}
	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// KillConflictingProcesses stops NetworkManager and wpa_supplicant.
func KillConflictingProcesses() error {
	return DefaultDriver.KillConflictingProcesses()
}

func (d *WirelessDriver) KillConflictingProcesses() error {
	commands := [][]string{
		{"systemctl", "stop", "NetworkManager"},
		{"systemctl", "stop", "wpa_supplicant"},
	}

	for _, cmdParts := range commands {
		cmdName := cmdParts[0]
		cmdArgs := cmdParts[1:]
		out, err := d.executor.Execute(cmdName, cmdArgs...)
		if err != nil {
			return fmt.Errorf("failed to execute %s %v: %v (%s)", cmdName, cmdArgs, err, string(out))
		}
	}
	return nil
}

// RestoreNetworkServices restarts NetworkManager and wpa_supplicant.
func RestoreNetworkServices() error {
	return DefaultDriver.RestoreNetworkServices()
}

func (d *WirelessDriver) RestoreNetworkServices() error {
	commands := [][]string{
		{"systemctl", "start", "wpa_supplicant"},
		{"systemctl", "start", "NetworkManager"},
	}

	var lastErr error
	for _, cmdParts := range commands {
		cmdName := cmdParts[0]
		cmdArgs := cmdParts[1:]
		out, err := d.executor.Execute(cmdName, cmdArgs...)
		if err != nil {
			lastErr = fmt.Errorf("failed to execute %s %v: %v (%s)", cmdName, cmdArgs, err, string(out))
		}
	}
	return lastErr
}

// EnableMonitorMode puts the interface into monitor mode
func EnableMonitorMode(iface string) error {
	return DefaultDriver.EnableMonitorMode(iface)
}

func (d *WirelessDriver) EnableMonitorMode(iface string) error {
	log.Printf("Enabling monitor mode on %s...", iface)

	if err := d.runCmd("ip", "link", "set", iface, "down"); err != nil {
		return err
	}

	if err := d.runCmd("iw", iface, "set", "type", "monitor"); err != nil {
		log.Printf("Error setting monitor mode. Hint: try killing conflicting processes.")
		return err
	}

	// Set default channel
	_ = d.SetInterfaceChannel(iface, 6)

	if err := d.runCmd("ip", "link", "set", iface, "up"); err != nil {
		return err
	}
	return nil
}

// DisableMonitorMode puts the interface back into managed mode
func DisableMonitorMode(iface string) {
	DefaultDriver.DisableMonitorMode(iface)
}

func (d *WirelessDriver) DisableMonitorMode(iface string) {
	log.Printf("Restoring managed mode on %s...", iface)
	_ = d.runCmd("ip", "link", "set", iface, "down")
	_ = d.runCmd("iw", iface, "set", "type", "managed")
	_ = d.runCmd("ip", "link", "set", iface, "up")
}

func (d *WirelessDriver) runCmd(name string, args ...string) error {
	output, err := d.executor.Execute(name, args...)
	if err != nil {
		log.Printf("Command failed: %s %v\nOutput: %s", name, args, string(output))
		return err
	}
	return nil
}
