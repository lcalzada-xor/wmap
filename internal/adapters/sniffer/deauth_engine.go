package sniffer

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// AttackController manages the lifecycle of a single deauth attack
type AttackController struct {
	ID       string
	Config   domain.DeauthAttackConfig
	Status   domain.DeauthAttackStatus
	CancelFn context.CancelFunc
	StatusCh chan domain.DeauthAttackStatus
	mu       sync.RWMutex
}

// DeauthEngine manages multiple concurrent deauth attacks
type DeauthEngine struct {
	injector      *Injector
	activeAttacks map[string]*AttackController
	mu            sync.RWMutex
	maxConcurrent int
}

// NewDeauthEngine creates a new deauth attack engine
func NewDeauthEngine(injector *Injector, maxConcurrent int) *DeauthEngine {
	if maxConcurrent <= 0 {
		maxConcurrent = 5 // Default max concurrent attacks
	}
	return &DeauthEngine{
		injector:      injector,
		activeAttacks: make(map[string]*AttackController),
		maxConcurrent: maxConcurrent,
	}
}

// StartAttack initiates a new deauth attack
func (e *DeauthEngine) StartAttack(config domain.DeauthAttackConfig) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check concurrent attack limit
	if len(e.activeAttacks) >= e.maxConcurrent {
		return "", fmt.Errorf("maximum concurrent attacks (%d) reached", e.maxConcurrent)
	}

	// Validate configuration
	if config.TargetMAC == "" {
		return "", fmt.Errorf("target MAC is required")
	}

	if config.AttackType == domain.DeauthUnicast || config.AttackType == domain.DeauthTargeted {
		if config.ClientMAC == "" {
			return "", fmt.Errorf("client MAC is required for %s attack", config.AttackType)
		}
	}

	// Generate unique attack ID
	attackID := uuid.New().String()

	// Create attack controller
	ctx, cancel := context.WithCancel(context.Background())
	statusCh := make(chan domain.DeauthAttackStatus, 10)

	controller := &AttackController{
		ID:       attackID,
		Config:   config,
		CancelFn: cancel,
		StatusCh: statusCh,
		Status: domain.DeauthAttackStatus{
			ID:          attackID,
			Config:      config,
			Status:      domain.AttackPending,
			PacketsSent: 0,
			StartTime:   time.Now(),
		},
	}

	e.activeAttacks[attackID] = controller

	// Start the attack in a goroutine
	go e.runAttack(ctx, controller)

	log.Printf("[DEAUTH] Started attack %s: Type=%s Target=%s", attackID, config.AttackType, config.TargetMAC)

	return attackID, nil
}

// runAttack executes the attack logic
func (e *DeauthEngine) runAttack(ctx context.Context, controller *AttackController) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[DEAUTH] Attack %s panicked: %v", controller.ID, r)
			controller.mu.Lock()
			controller.Status.Status = domain.AttackFailed
			controller.Status.ErrorMessage = fmt.Sprintf("panic: %v", r)
			now := time.Now()
			controller.Status.EndTime = &now
			controller.mu.Unlock()
		}
	}()

	// Update status to running
	controller.mu.Lock()
	controller.Status.Status = domain.AttackRunning
	controller.mu.Unlock()

	config := controller.Config

	// Determine if continuous or burst
	if config.PacketCount == 0 {
		// Continuous attack
		if err := e.injector.StartContinuousDeauth(ctx, config, controller.StatusCh); err != nil {
			log.Printf("[DEAUTH] Continuous attack %s failed: %v", controller.ID, err)
			controller.mu.Lock()
			controller.Status.Status = domain.AttackFailed
			controller.Status.ErrorMessage = err.Error()
			controller.mu.Unlock()
		}
	} else {
		// Burst attack
		if err := e.injector.SendDeauthBurst(config); err != nil {
			log.Printf("[DEAUTH] Burst attack %s failed: %v", controller.ID, err)
			controller.mu.Lock()
			controller.Status.Status = domain.AttackFailed
			controller.Status.ErrorMessage = err.Error()
			controller.mu.Unlock()
		} else {
			controller.mu.Lock()
			controller.Status.PacketsSent = config.PacketCount
			controller.Status.Status = domain.AttackStopped
			controller.mu.Unlock()
		}
	}

	// Mark as completed
	controller.mu.Lock()
	if controller.Status.Status == domain.AttackRunning {
		controller.Status.Status = domain.AttackStopped
	}
	now := time.Now()
	controller.Status.EndTime = &now
	controller.mu.Unlock()

	log.Printf("[DEAUTH] Attack %s completed: PacketsSent=%d Status=%s",
		controller.ID, controller.Status.PacketsSent, controller.Status.Status)
}

// StopAttack stops a running attack
func (e *DeauthEngine) StopAttack(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()

	if controller.Status.Status != domain.AttackRunning && controller.Status.Status != domain.AttackPaused {
		return fmt.Errorf("attack %s is not active (status: %s)", id, controller.Status.Status)
	}

	// Cancel the context to stop the attack
	controller.CancelFn()
	controller.Status.Status = domain.AttackStopped
	now := time.Now()
	controller.Status.EndTime = &now

	log.Printf("[DEAUTH] Stopped attack %s", id)

	return nil
}

// PauseAttack pauses a running attack (not fully implemented - would need more complex state management)
func (e *DeauthEngine) PauseAttack(id string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
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

	log.Printf("[DEAUTH] Paused attack %s", id)

	return nil
}

// ResumeAttack resumes a paused attack (placeholder)
func (e *DeauthEngine) ResumeAttack(id string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return fmt.Errorf("attack %s not found", id)
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
func (e *DeauthEngine) GetAttackStatus(id string) (domain.DeauthAttackStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	controller, exists := e.activeAttacks[id]
	if !exists {
		return domain.DeauthAttackStatus{}, fmt.Errorf("attack %s not found", id)
	}

	controller.mu.RLock()
	defer controller.mu.RUnlock()

	return controller.Status, nil
}

// ListActiveAttacks returns all active attacks
func (e *DeauthEngine) ListActiveAttacks() []domain.DeauthAttackStatus {
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
	defer e.mu.Unlock()

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

	if removed > 0 {
		log.Printf("[DEAUTH] Cleaned up %d finished attacks", removed)
	}

	return removed
}

// StopAll stops all active attacks
func (e *DeauthEngine) StopAll() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for id := range e.activeAttacks {
		if err := e.StopAttack(id); err != nil {
			log.Printf("[DEAUTH] Failed to stop attack %s: %v", id, err)
		}
	}

	log.Printf("[DEAUTH] Stopped all attacks")
}
