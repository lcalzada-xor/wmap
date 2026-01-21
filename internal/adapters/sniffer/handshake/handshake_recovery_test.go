package handshake

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHandshakeManager_Recovery verifies that we can capture a handshake
// even if we miss M1, by recovering context from M3.
func TestHandshakeManager_Recovery(t *testing.T) {
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	bssid := "00:11:22:33:44:bb"
	client := "aa:bb:cc:dd:ee:11"

	// 1. Simulate missed M1.
	// We go straight to receiving M2 (STA->AP).
	// RC=10.
	p2 := createEAPOLPacket(client, bssid, bssid, 2, 10)
	saved := hm.ProcessFrame(p2)
	assert.False(t, saved, "M2 alone should not save")

	// Verify session state
	hm.mu.RLock()
	session, exists := hm.sessions[bssid+"_"+client]
	hm.mu.RUnlock()

	assert.True(t, exists, "Session should be created on M2")
	assert.True(t, session.Captured[2], "M2 should be captured")
	assert.Nil(t, session.Anonce, "Anonce should be nil (missed M1)")

	// 2. Simulate M3 (AP->STA).
	// RC=11.
	// This frame contains the ANonce.
	p3 := createEAPOLPacket(bssid, client, bssid, 3, 11)

	// We need to ensure p3 has a valid Nonce we can check later?
	// createEAPOLPacket generates zero-nonce by default?
	// The helper in manager_test seems to put 0s.
	// Let's rely on default behavior.

	saved = hm.ProcessFrame(p3)
	assert.True(t, saved, "M2+M3 should be enough to save")

	// Verify recovered state
	hm.mu.RLock()
	session = hm.sessions[bssid+"_"+client]
	hm.mu.RUnlock()

	assert.NotNil(t, session.Anonce, "Anonce should be recovered from M3")
	assert.True(t, session.Captured[3], "M3 should be captured")
	assert.True(t, hm.HasHandshake(bssid), "Handshake should be valid")
}

// Helper duplicated from manager_test (since it's not exported)
// In a real scenario, we should export it or put this test in the same file.
// Since we are in the same package `handshake`, we can access `createEAPOLPacket`
// IF it is in the `handshake` package (not `handshake_test` package).
// `handshake_manager_test.go` says `package handshake`. So we can reuse it!
