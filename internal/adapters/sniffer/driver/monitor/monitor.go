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

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/channel"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/iface"
)

const (
	verifyAttempts  = 5
	verifyInterval  = 400 * time.Millisecond
	cmdTimeout      = 10 * time.Second
	defaultChannel  = 6
)

// Enable puts iface into monitor mode and blocks until the kernel confirms it
// (or returns an error after verifyAttempts × verifyInterval).
func Enable(exec executor.CommandExecutor, ifaceName string) (err error) {
	log.Printf("Enabling monitor mode on %s...", ifaceName)

	// Snapshot the current mode so we can roll back on failure.
	originalMode := snapshotMode(exec, ifaceName)
	if originalMode == "monitor" {
		log.Printf("Interface %s is already in monitor mode", ifaceName)
		return runCmd(exec, "ip", "link", "set", ifaceName, "up")
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

	// Prime a default channel (best-effort; not fatal).
	_ = channel.Set(exec, ifaceName, defaultChannel)

	if err = runCmd(exec, "ip", "link", "set", ifaceName, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", ifaceName, err)
	}

	// Verify the mode sticks — some drivers (iwlmvm) or a surviving
	// NetworkManager instance can flip it back within milliseconds.
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
