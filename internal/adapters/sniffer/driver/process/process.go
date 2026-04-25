// Package process manages conflicting system services (NetworkManager,
// wpa_supplicant) that would interfere with monitor-mode packet capture.
// It provides a robust kill sequence that waits for processes to truly die
// before returning (critical for chipsets like iwlmvm which reconnect in < 5 s
// if NetworkManager is still alive when the interface enters monitor mode).
package process

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
)

// conflictingProcs is the ordered list of services / processes to suspend
// before entering monitor mode and to restore afterwards.
var conflictingProcs = []string{"NetworkManager", "wpa_supplicant"}

// StopConflicting stops NetworkManager and wpa_supplicant and waits for them
// to actually terminate before returning. Any stragglers are SIGKILL'd.
func StopConflicting(exec executor.CommandExecutor) error {
	log.Println("Stopping conflicting network processes...")

	// Phase 1: request graceful stop via systemctl.
	for _, svc := range conflictingProcs {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		out, err := exec.Execute(ctx, "systemctl", "stop", svc)
		cancel()
		if err != nil {
			log.Printf("Warning: systemctl stop %s: %v (%s)", svc, err, strings.TrimSpace(string(out)))
		}
	}

	// Phase 2: poll until all processes are gone (up to 4 s total).
	// iwlmvm chipsets reconnect to the AP if NetworkManager is still alive
	// when we flip to monitor mode, so we must be sure it is truly gone.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if allDead(exec, conflictingProcs) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Phase 3: SIGKILL stragglers.
	for _, name := range conflictingProcs {
		pid := pidOf(exec, name)
		if pid == "" {
			continue
		}
		log.Printf("Warning: %s still alive (pid %s), sending SIGKILL", name, pid)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		exec.Execute(ctx, "kill", "-9", pid) //nolint:errcheck
		cancel()
	}

	// Brief pause to let the kernel process the terminations.
	time.Sleep(300 * time.Millisecond)
	return nil
}

// RestoreConflicting restarts the services that were stopped before capture.
func RestoreConflicting(exec executor.CommandExecutor) error {
	log.Println("Restoring network services...")

	// Restore in reverse order: wpa_supplicant first, then NetworkManager.
	order := []string{"wpa_supplicant", "NetworkManager"}
	var errs []string
	for _, svc := range order {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.Execute(ctx, "systemctl", "start", svc)
		cancel()
		if err != nil {
			msg := fmt.Sprintf("failed to start %s: %v (%s)", svc, err, strings.TrimSpace(string(out)))
			log.Printf("Warning: %s", msg)
			errs = append(errs, msg)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors restoring services: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func allDead(exec executor.CommandExecutor, names []string) bool {
	for _, name := range names {
		if pidOf(exec, name) != "" {
			return false
		}
	}
	return true
}

func pidOf(exec executor.CommandExecutor, name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.Execute(ctx, "pgrep", "-x", name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
