// Package driver is the public façade for all wireless-interface management.
// It wires together the sub-packages (executor, iface, capabilities, channel,
// monitor, process) and exposes a stable API used by the rest of the
// application.  Callers should import only this package; the sub-packages are
// internal implementation details.
package driver

import (
	"context"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/capabilities"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/channel"
	driverexec "github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/iface"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/monitor"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/process"
)

// ── CommandExecutor re-export ─────────────────────────────────────────────────

// CommandExecutor is the abstraction used by every sub-package to run system
// commands.  It is re-exported here so callers that only import "driver" can
// still implement mocks without depending on the internal executor package.
type CommandExecutor = driverexec.CommandExecutor

// ── Default driver instance ───────────────────────────────────────────────────

// defaultExec is the singleton executor used by all top-level helpers.
var defaultExec CommandExecutor = driverexec.System{}

// SetExecutor replaces the default command executor.  Call this in tests to
// inject a mock before invoking any of the package-level functions.
func SetExecutor(e CommandExecutor) {
	defaultExec = e
}

// ── Capabilities ──────────────────────────────────────────────────────────────

// GetInterfaceCapabilities returns the set of supported bands, the list of
// supported channel numbers, and a channel→frequency map for iface's underlying PHY.
func GetInterfaceCapabilities(iface string) (map[string]bool, []int, map[int]int, error) {
	res, err := capabilities.Get(defaultExec, iface)
	if err != nil {
		return nil, nil, nil, err
	}
	return res.Bands, res.Channels, res.ChannelFreq, nil
}

// ── Interface state ───────────────────────────────────────────────────────────

// GetInterfaceCurrentConfig returns the current operating mode and TX power
// (dBm) for iface.
func GetInterfaceCurrentConfig(ifaceName string) (string, int, error) {
	cfg, err := iface.GetCurrentConfig(defaultExec, ifaceName)
	if err != nil {
		return "unknown", 0, err
	}
	return cfg.Mode, cfg.TxPower, nil
}

// GetDriverInfo returns the kernel driver name for iface (e.g. "iwlwifi").
func GetDriverInfo(ifaceName string) (string, error) {
	return iface.GetDriverName(defaultExec, ifaceName)
}

// ── Channel management ────────────────────────────────────────────────────────

// SetInterfaceChannel tunes iface to the given channel number.
func SetInterfaceChannel(ifaceName string, ch int) error {
	return channel.Set(defaultExec, ifaceName, ch)
}

// SetInterfaceChannelWithRetry tries to set the channel up to maxRetries times.
func SetInterfaceChannelWithRetry(ifaceName string, ch, maxRetries int) error {
	return channel.SetWithRetry(defaultExec, ifaceName, ch, maxRetries)
}

// SetInterfaceDown brings iface down (ip link set <iface> down).
func SetInterfaceDown(ifaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := defaultExec.Execute(ctx, "ip", "link", "set", ifaceName, "down")
	return err
}

// SetInterfaceUp brings iface up (ip link set <iface> up).
func SetInterfaceUp(ifaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := defaultExec.Execute(ctx, "ip", "link", "set", ifaceName, "up")
	return err
}

// ── Monitor mode ──────────────────────────────────────────────────────────────

// EnableMonitorMode transitions iface into monitor mode and verifies it stuck.
func EnableMonitorMode(ifaceName string) error {
	return monitor.Enable(defaultExec, ifaceName)
}

// DisableMonitorMode returns iface to managed mode.
func DisableMonitorMode(ifaceName string) {
	monitor.Disable(defaultExec, ifaceName)
}

// ── Process management ────────────────────────────────────────────────────────

// KillConflictingProcesses stops NetworkManager and wpa_supplicant and waits
// for them to actually terminate before returning.
func KillConflictingProcesses() error {
	return process.StopConflicting(defaultExec)
}

// RestoreNetworkServices restarts the services stopped by KillConflictingProcesses.
func RestoreNetworkServices() error {
	return process.RestoreConflicting(defaultExec)
}
