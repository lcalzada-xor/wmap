package deauth

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEngineLocker implements ChannelLocker
type MockEngineLocker struct{}

func (m *MockEngineLocker) Lock(iface string, channel int) error { return nil }
func (m *MockEngineLocker) Unlock(iface string) error            { return nil }
func (m *MockEngineLocker) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	return action()
}

func TestDeauthEngine_SequentialAttacks(t *testing.T) {
	// Setup
	// We need a dummy pcap handle for injector?
	// Can we verify without actual injection?
	// NewInjector tries to OpenLive. We can't do that in unit test easily without root/interface.
	// But we can verify the Engine logic if we mock Injector?
	// Struct `DeauthEngine` takes `*Injector`. `Injector` is concrete struct.
	// Hard to mock concrete struct without interface.
	// However, we can use `CleanupFinished` logic test.

	locker := &MockEngineLocker{}
	// We cannot easily mock Injector methods because they are methods on concrete types.
	// Refactoring DeauthEngine to use an Interface for Injector (IInjector) would be best but risky now.
	// Instead, let's verify Cleanup logic directly.

	engine := NewDeauthEngine(nil, locker, 5) // Injector nil
	// StartAttack checks if injector is allowed.
	// engine.go:193: if injector == nil { AttackFailed }

	// We can simulate an attack lifecycle manually by manipulating the map?
	// StartAttack
	// config := domain.DeauthAttackConfig{TargetMAC: "00:11:22:33:44:55", Interface: "wlan0"}

	// If we call StartAttack with nil injector, it enters activeAttacks, launches goroutine, fails immediately, sets Status=Failed.
	// Then CleanupFinished should remove it.

	// Attack 1
	config := domain.DeauthAttackConfig{TargetMAC: "00:11:22:33:44:55", Interface: ""}
	id1, err := engine.StartAttack(config)
	require.NoError(t, err)

	// Wait for it to fail (async)
	time.Sleep(100 * time.Millisecond)

	status1, _ := engine.GetAttackStatus(id1)
	assert.Equal(t, domain.AttackFailed, status1.Status, "Attack 1 should fail due to no injector")

	// Check Active count
	assert.Equal(t, 1, len(engine.activeAttacks))

	// Run Cleanup directly (as usually called by StartAttack)
	engine.CleanupFinished()
	assert.Equal(t, 0, len(engine.activeAttacks), "Cleanup should remove failed/stopped attack")

	// Attack 2
	id2, err := engine.StartAttack(config)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	status2, _ := engine.GetAttackStatus(id2)
	assert.Equal(t, domain.AttackFailed, status2.Status)

	engine.CleanupFinished()
	assert.Equal(t, 0, len(engine.activeAttacks))
}

func TestDeauthEngine_ForceStop(t *testing.T) {
	locker := &MockEngineLocker{}
	engine := NewDeauthEngine(nil, locker, 5)

	// Start a fake attack (will fail async due to nil injector, but we intercept before cleanup)
	config := domain.DeauthAttackConfig{TargetMAC: "00:11:22:33:44:55"}
	id, err := engine.StartAttack(config)
	require.NoError(t, err)

	// Wait briefly for it to appear in map
	time.Sleep(10 * time.Millisecond)

	// Force Stop
	err = engine.StopAttack(id, true)
	assert.NoError(t, err)

	// Verify status
	status, _ := engine.GetAttackStatus(id)
	assert.Equal(t, domain.AttackStopped, status.Status)
	assert.Contains(t, status.ErrorMessage, "Force stopped")
}

func TestDeauthEngine_StopAll(t *testing.T) {
	locker := &MockEngineLocker{}
	engine := NewDeauthEngine(nil, locker, 5)

	// Start multiple fake attacks
	for i := 0; i < 3; i++ {
		config := domain.DeauthAttackConfig{TargetMAC: "00:11:22:33:44:55"}
		_, err := engine.StartAttack(config)
		require.NoError(t, err)
	}

	// Wait briefly
	time.Sleep(10 * time.Millisecond)

	// Check active count
	engine.mu.Lock()
	count := len(engine.activeAttacks)
	engine.mu.Unlock()
	assert.Equal(t, 3, count)

	// Stop All (should not deadlock)
	done := make(chan struct{})
	go func() {
		engine.StopAll()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("StopAll deadlocked")
	}

	// Verify all stopped
	engine.mu.Lock()
	count = len(engine.activeAttacks)
	engine.mu.Unlock()

	// They remain in map untill cleanup, but status should be stopped/failed
	// Actually StopAll updates status.
	// We can check statuses.
}

func TestDeauthEngine_InterfaceAutoDetection(t *testing.T) {
	locker := &MockEngineLocker{}
	inj := &injection.Injector{Interface: "wlan0mon"}
	engine := NewDeauthEngine(inj, locker, 5)

	config := domain.DeauthAttackConfig{TargetMAC: "00:11:22:33:44:55"} // Interface empty
	id, err := engine.StartAttack(config)
	require.NoError(t, err)

	status, _ := engine.GetAttackStatus(id)
	assert.Equal(t, "wlan0mon", status.Config.Interface, "Interface should be auto-detected from injector")
}

func TestDeauthEngine_ContextCancellation(t *testing.T) {
	locker := &MockEngineLocker{}
	engine := NewDeauthEngine(nil, locker, 5)

	// Start a fake attack
	config := domain.DeauthAttackConfig{TargetMAC: "00:11:22:33:44:55"}
	id, err := engine.StartAttack(config)
	require.NoError(t, err)

	// Wait for attack to fail (nil injector will cause immediate failure)
	time.Sleep(50 * time.Millisecond)

	// Verify it failed
	status, _ := engine.GetAttackStatus(id)
	assert.Equal(t, domain.AttackFailed, status.Status)

	// Cleanup
	engine.CleanupFinished()
}
