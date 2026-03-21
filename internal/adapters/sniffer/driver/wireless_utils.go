package driver

import (
	"bufio"
	"bytes"
	"context"
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
	Execute(ctx context.Context, name string, args ...string) ([]byte, error)
}

// SystemCommandExecutor implements CommandExecutor using os/exec
type SystemCommandExecutor struct{}

func (e *SystemCommandExecutor) Execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
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

const (
	FreqBoundary24GHz   = 4000
	FreqBoundary5GHzMin = 4900
	FreqBoundary5GHzMax = 5900
)

var reFreqChan = regexp.MustCompile(`\*\s+([0-9]+)(\.[0-9]+)?\s+MHz\s+\[([0-9]+)\]`)

// GetInterfaceCapabilities returns the supported channels for a given interface.
func GetInterfaceCapabilities(iface string) (map[string]bool, []int, error) {
	return DefaultDriver.GetInterfaceCapabilities(iface)
}

func (d *WirelessDriver) GetInterfaceCapabilities(iface string) (map[string]bool, []int, error) {
	// 1. Map Interface -> Phy
	phy, err := d.getPhyForInterface(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("getting phy for interface %s: %w", iface, err)
	}

	// 2. Get Phy Capabilities
	return d.getPhyCapabilities(phy)
}

func (d *WirelessDriver) getPhyForInterface(iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := d.executor.Execute(ctx, "iw", "dev")
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := d.executor.Execute(ctx, "iw", "phy", phy, "info")
	if err != nil {
		return nil, nil, fmt.Errorf("getting phy capabilities for %s: %w", phy, err)
	}

	bands := make(map[string]bool)
	supportedChannels := []int{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inFrequencies := false

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

				matches := reFreqChan.FindStringSubmatch(line)
				if len(matches) > 3 {
					freq, _ := strconv.Atoi(matches[1])
					ch, _ := strconv.Atoi(matches[3]) // Group 3 is channel now

					supportedChannels = append(supportedChannels, ch)

					// Frequency-based detection is more robust
					if freq < FreqBoundary24GHz {
						bands["2.4GHz"] = true // Match domain.Band24GHz
					} else if freq >= FreqBoundary5GHzMin && freq < FreqBoundary5GHzMax {
						bands["5GHz"] = true // Match domain.Band5GHz
					} else if freq >= FreqBoundary5GHzMax {
						bands["6GHz"] = true // Match domain.Band6GHz
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := d.executor.Execute(ctx, "iw", iface, "set", "channel", fmt.Sprintf("%d", channel))
	if err != nil {
		return fmt.Errorf("failed to set channel %d on %s: %w (%s)", channel, iface, err, string(output))
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
	log.Println("Stopping conflicting network processes...")
	commands := [][]string{
		{"systemctl", "stop", "NetworkManager"},
		{"systemctl", "stop", "wpa_supplicant"},
	}

	var errs []string
	for _, cmdParts := range commands {
		cmdName := cmdParts[0]
		cmdArgs := cmdParts[1:]
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := d.executor.Execute(ctx, cmdName, cmdArgs...)
		cancel()
		if err != nil {
			msg := fmt.Sprintf("failed to stop %s: %v (%s)", cmdArgs[1], err, strings.TrimSpace(string(out)))
			log.Printf("Warning: %s", msg)
			errs = append(errs, msg)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered errors stopping processes: %s", strings.Join(errs, "; "))
	}
	return nil
}

// RestoreNetworkServices restarts NetworkManager and wpa_supplicant.
func RestoreNetworkServices() error {
	return DefaultDriver.RestoreNetworkServices()
}

func (d *WirelessDriver) RestoreNetworkServices() error {
	log.Println("Restoring network services...")
	commands := [][]string{
		{"systemctl", "start", "wpa_supplicant"},
		{"systemctl", "start", "NetworkManager"},
	}

	var errs []string
	for _, cmdParts := range commands {
		cmdName := cmdParts[0]
		cmdArgs := cmdParts[1:]
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := d.executor.Execute(ctx, cmdName, cmdArgs...)
		cancel()
		if err != nil {
			msg := fmt.Sprintf("failed to start %s: %v (%s)", cmdArgs[1], err, strings.TrimSpace(string(out)))
			log.Printf("Warning: %s", msg)
			errs = append(errs, msg)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered errors restoring processes: %s", strings.Join(errs, "; "))
	}
	return nil
}

// EnableMonitorMode puts the interface into monitor mode
func EnableMonitorMode(iface string) error {
	return DefaultDriver.EnableMonitorMode(iface)
}

func (d *WirelessDriver) EnableMonitorMode(iface string) (err error) {
	log.Printf("Enabling monitor mode on %s...", iface)

	// Get current interface state before making changes
	originalMode, _, getErr := d.GetInterfaceCurrentConfig(iface)
	if getErr != nil {
		log.Printf("Warning: Could not get current interface state for %s: %v", iface, getErr)
		originalMode = "unknown"
	}

	if originalMode == "monitor" {
		log.Printf("Interface %s is already in monitor mode", iface)
		return d.runCmd("ip", "link", "set", iface, "up")
	}

	needsRestore := false
	defer func() {
		if err != nil && needsRestore {
			log.Printf("Error enabling monitor mode, rolling back %s to %s...", iface, originalMode)
			d.restoreInterfaceState(iface, originalMode)
		}
	}()

	// Try to bring interface down
	if err = d.runCmd("ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}
	needsRestore = true

	// Try to set monitor mode
	if err = d.runCmd("iw", iface, "set", "type", "monitor"); err != nil {
		return fmt.Errorf("failed to set monitor mode: %w", err)
	}

	// Set default channel (non-critical, don't fail if this doesn't work)
	_ = d.SetInterfaceChannel(iface, 6)

	// Bring interface up
	if err = d.runCmd("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// restoreInterfaceState attempts to restore an interface to its original mode
func (d *WirelessDriver) restoreInterfaceState(iface string, originalMode string) {
	log.Printf("Attempting to restore %s to original mode: %s", iface, originalMode)

	// First bring interface down
	if err := d.runCmd("ip", "link", "set", iface, "down"); err != nil {
		log.Printf("Warning: failed to bring interface down during restore for %s: %v", iface, err)
	}

	// Try to restore to original mode if we know it
	if originalMode != "unknown" && originalMode != "" {
		_ = d.runCmd("iw", iface, "set", "type", originalMode)
	} else {
		// Default to managed mode if we don't know the original
		_ = d.runCmd("iw", iface, "set", "type", "managed")
	}

	// Bring interface back up
	_ = d.runCmd("ip", "link", "set", iface, "up")

	log.Printf("Interface %s restoration attempted", iface)
}

// DisableMonitorMode puts the interface back into managed mode
func DisableMonitorMode(iface string) {
	DefaultDriver.DisableMonitorMode(iface)
}

func (d *WirelessDriver) DisableMonitorMode(iface string) {
	log.Printf("Restoring managed mode on %s...", iface)
	if err := d.runCmd("ip", "link", "set", iface, "down"); err != nil {
		log.Printf("Warning: failed to bring interface down for %s: %v", iface, err)
	}
	if err := d.runCmd("iw", iface, "set", "type", "managed"); err != nil {
		log.Printf("Warning: failed to set managed mode for %s: %v", iface, err)
	}
	if err := d.runCmd("ip", "link", "set", iface, "up"); err != nil {
		log.Printf("Warning: failed to bring interface up for %s: %v", iface, err)
	}
}

func (d *WirelessDriver) runCmd(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := d.executor.Execute(ctx, name, args...)
	if err != nil {
		log.Printf("Command failed: %s %v\nOutput: %s", name, args, string(output))
		return fmt.Errorf("executing %s %v: %w", name, args, err)
	}
	return nil
}

// GetDriverInfo returns the driver name for the interface.
func GetDriverInfo(iface string) (string, error) {
	return DefaultDriver.GetDriverInfo(iface)
}

func (d *WirelessDriver) GetDriverInfo(iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try ethtool first (standard for driver info)
	// Output format:
	// driver: iwlwifi
	// ...
	out, err := d.executor.Execute(ctx, "ethtool", "-i", iface)
	if err != nil {
		// Fallback? Maybe /sys/class/net/<iface>/device/driver/module
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "driver:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "driver:")), nil
		}
	}
	return "unknown", nil
}

// GetInterfaceCurrentConfig returns current Mode and TxPower
func GetInterfaceCurrentConfig(iface string) (string, int, error) {
	return DefaultDriver.GetInterfaceCurrentConfig(iface)
}

func (d *WirelessDriver) GetInterfaceCurrentConfig(iface string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := d.executor.Execute(ctx, "iw", "dev", iface, "info")
	if err != nil {
		return "", 0, err
	}

	// Output example:
	// Interface wlan0
	// 	ifindex 3
	// 	wdev 0x1
	// 	addr ...
	// 	type managed
	// 	wiphy 0
	// 	channel 1 (2412 MHz), width: 20 MHz, center1: 2412 MHz
	// 	txpower 20.00 dBm

	mode := "unknown"
	txPower := 0

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "type ") {
			mode = strings.TrimPrefix(line, "type ")
		} else if strings.HasPrefix(line, "txpower ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, err := strconv.ParseFloat(parts[1], 64)
				if err == nil {
					txPower = int(val)
				}
			}
		}
	}

	return mode, txPower, nil
}
