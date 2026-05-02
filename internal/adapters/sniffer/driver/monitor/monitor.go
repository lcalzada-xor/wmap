// Package monitor handles transitioning a wireless interface into and out of
// monitor mode. It includes a post-activation verification loop to cope with
// drivers (e.g. iwlmvm on Intel AX chipsets) whose "monitor" mode is
// implemented in software and can be reverted by NetworkManager within seconds.
package monitor

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/iface"
)

const (
	verifyAttempts = 5
	verifyInterval = 400 * time.Millisecond
	cmdTimeout     = 10 * time.Second
)

// Enable puts iface into monitor mode and blocks until the kernel confirms it
// (or returns an error after verifyAttempts × verifyInterval).
//
// It always performs a hard reset via "iw dev <iface> del" + "iw phy <phy>
// interface add <iface> type monitor flags fcsfail otherbss" so that the driver
// discards any state left over from a previous session and the interface is
// configured for passive promiscuous capture from the start.
//
// The "otherbss" flag is required on drivers that implement active monitor
// (e.g. mt7921u) — without it the hardware filters out frames not addressed to
// the interface's own MAC before they reach pcap. "fcsfail" passes through
// frames with bad FCS so they can be counted for diagnostic purposes.
func Enable(exec executor.CommandExecutor, ifaceName string) (err error) {
	log.Printf("Enabling monitor mode on %s...", ifaceName)

	phy, phyErr := iface.GetPhy(exec, ifaceName)
	if phyErr != nil {
		log.Printf("Warning: could not resolve PHY for %s (%v), using legacy path", ifaceName, phyErr)
		return enableLegacy(exec, ifaceName)
	}

	// Hard-reset: delete the virtual interface and recreate it clean.
	_ = runCmd(exec, "ip", "link", "set", ifaceName, "down")
	if err = runCmd(exec, "iw", "dev", ifaceName, "del"); err != nil {
		log.Printf("Warning: could not delete %s (%v), using legacy path", ifaceName, err)
		return enableLegacy(exec, ifaceName)
	}

	// Recreate with otherbss flag. This disables the hardware MAC filter so
	// frames from all BSSes reach pcap — required on drivers that implement
	// active monitor (e.g. mt7921u) where the default filters by own MAC.
	// We deliberately omit "fcsfail": passing FCS-corrupted frames to the
	// parser produces garbage SSIDs and phantom devices.
	if err = runCmd(exec, "iw", phy, "interface", "add", ifaceName,
		"type", "monitor", "flags", "otherbss"); err != nil {
		// Some older kernels/drivers don't accept flags at creation time — retry without.
		log.Printf("Warning: monitor with flags failed on %s (%v), retrying without flags", ifaceName, err)
		if err = runCmd(exec, "iw", phy, "interface", "add", ifaceName, "type", "monitor"); err != nil {
			return fmt.Errorf("recreate %s as monitor on %s: %w", ifaceName, phy, err)
		}
	}

	if err = runCmd(exec, "ip", "link", "set", ifaceName, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", ifaceName, err)
	}

	// Set monitor flags after up — covers all paths including the fallback.
	_ = runCmd(exec, "iw", ifaceName, "set", "monitor", "otherbss")

	// Verify the mode sticks.
	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		time.Sleep(verifyInterval)
		current := snapshotMode(exec, ifaceName)
		if current == "monitor" {
			log.Printf("Interface %s confirmed in monitor mode after %d attempt(s)", ifaceName, attempt)
			return nil
		}
		log.Printf("Warning: %s is still in '%s' mode (attempt %d/%d), retrying...",
			ifaceName, current, attempt, verifyAttempts)
		_ = runCmd(exec, "ip", "link", "set", ifaceName, "down")
		_ = runCmd(exec, "iw", ifaceName, "set", "type", "monitor")
		_ = runCmd(exec, "ip", "link", "set", ifaceName, "up")
	}

	return fmt.Errorf("%s failed to enter monitor mode after %d attempts "+
		"(check NetworkManager / driver support)", ifaceName, verifyAttempts)
}

// enableLegacy is the old down/type-monitor/up path used as fallback when we
// cannot resolve the PHY or delete the virtual interface.
func enableLegacy(exec executor.CommandExecutor, ifaceName string) (err error) {
	originalMode := snapshotMode(exec, ifaceName)
	if originalMode == "monitor" {
		// Already in monitor mode but we still cycle it down/up to flush any
		// residual driver state (stale pcap ring-buffer, old channel lock, etc.)
		// left over from a previous capture session.
		log.Printf("Warning: %s already in monitor mode — cycling link to flush residual driver state", ifaceName)
		_ = runCmd(exec, "ip", "link", "set", ifaceName, "down")
		_ = runCmd(exec, "ip", "link", "set", ifaceName, "up")
		return nil
	}

	needsRestore := false
	defer func() {
		if err != nil && needsRestore {
			log.Printf("Error enabling monitor mode, rolling back %s to '%s'...", ifaceName, originalMode)
			restore(exec, ifaceName, originalMode)
		}
	}()

	if err = runCmd(exec, "ip", "link", "set", ifaceName, "down"); err != nil {
		return fmt.Errorf("bring %s down: %w", ifaceName, err)
	}
	needsRestore = true

	if err = runCmd(exec, "iw", ifaceName, "set", "type", "monitor"); err != nil {
		return fmt.Errorf("set monitor type on %s: %w", ifaceName, err)
	}

	if err = runCmd(exec, "ip", "link", "set", ifaceName, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", ifaceName, err)
	}

	_ = runCmd(exec, "iw", ifaceName, "set", "monitor", "otherbss")

	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		time.Sleep(verifyInterval)
		current := snapshotMode(exec, ifaceName)
		if current == "monitor" {
			log.Printf("Interface %s confirmed in monitor mode after %d attempt(s)", ifaceName, attempt)
			return nil
		}
		log.Printf("Warning: %s is still in '%s' mode (attempt %d/%d), retrying...",
			ifaceName, current, attempt, verifyAttempts)
		_ = runCmd(exec, "ip", "link", "set", ifaceName, "down")
		_ = runCmd(exec, "iw", ifaceName, "set", "type", "monitor")
		_ = runCmd(exec, "ip", "link", "set", ifaceName, "up")
	}

	return fmt.Errorf("%s failed to enter monitor mode after %d attempts "+
		"(check NetworkManager / driver support)", ifaceName, verifyAttempts)
}

// Disable returns iface to managed mode.
func Disable(exec executor.CommandExecutor, ifaceName string) {
	log.Printf("Restoring managed mode on %s...", ifaceName)
	_ = runCmd(exec, "ip", "link", "set", ifaceName, "down")
	if err := runCmd(exec, "iw", ifaceName, "set", "type", "managed"); err != nil {
		log.Printf("Warning: set managed on %s: %v", ifaceName, err)
	}
	if err := runCmd(exec, "ip", "link", "set", ifaceName, "up"); err != nil {
		log.Printf("Warning: bring %s up (managed): %v", ifaceName, err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func snapshotMode(exec executor.CommandExecutor, ifaceName string) string {
	cfg, err := iface.GetCurrentConfig(exec, ifaceName)
	if err != nil {
		log.Printf("Warning: could not read mode for %s: %v", ifaceName, err)
		return "unknown"
	}
	return cfg.Mode
}

func restore(exec executor.CommandExecutor, ifaceName, originalMode string) {
	log.Printf("Attempting to restore %s to mode '%s'", ifaceName, originalMode)
	_ = runCmd(exec, "ip", "link", "set", ifaceName, "down")
	mode := originalMode
	if mode == "unknown" || mode == "" {
		mode = "managed"
	}
	_ = runCmd(exec, "iw", ifaceName, "set", "type", mode)
	_ = runCmd(exec, "ip", "link", "set", ifaceName, "up")
	log.Printf("Interface %s restoration attempted", ifaceName)
}

func runCmd(exec executor.CommandExecutor, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.Execute(ctx, name, args...)
	if err != nil {
		log.Printf("Command failed: %s %s\nOutput: %s",
			name, strings.Join(args, " "), string(out))
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
