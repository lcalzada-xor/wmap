package handshake

import (
	"testing"
	"time"
)

func TestHandshakeManager_CleanupSessions(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	// Manually inject a session
	// Manually inject sessions
	now := time.Now()
	expiredTime := now.Add(-10 * time.Minute)       // > 5 min (Always expire)
	inactiveIncomplete := now.Add(-1 * time.Minute) // > 30s (Expire if incomplete)
	activeIncomplete := now.Add(-10 * time.Second)  // < 30s (Keep)

	hm.sessions["expired_session"] = &HandshakeSession{
		BSSID:      "00:00:00:00:00:01",
		LastUpdate: expiredTime,
	}

	hm.sessions["inactive_incomplete"] = &HandshakeSession{
		BSSID:      "00:00:00:00:00:02",
		LastUpdate: inactiveIncomplete,
		Captured:   map[uint8]bool{1: true},
	}

	hm.sessions["active_incomplete"] = &HandshakeSession{
		BSSID:      "00:00:00:00:00:03",
		LastUpdate: activeIncomplete,
		Captured:   map[uint8]bool{1: true},
	}

	hm.sessions["active_complete"] = &HandshakeSession{
		BSSID:      "00:00:00:00:00:04",
		LastUpdate: inactiveIncomplete, // 1 min old (Should keep because complete)
		Captured:   map[uint8]bool{1: true, 2: true, 3: true, 4: true},
	}

	// Run cleanup
	hm.CleanupSessions()

	// Verify
	if _, exists := hm.sessions["expired_session"]; exists {
		t.Error("Expired session was not cleaned up")
	}
	if _, exists := hm.sessions["inactive_incomplete"]; exists {
		t.Error("Inactive incomplete session was not cleaned up (should timeout > 30s)")
	}
	if _, exists := hm.sessions["active_incomplete"]; !exists {
		t.Error("Active incomplete session was cleaned up incorrectly")
	}
	if _, exists := hm.sessions["active_complete"]; !exists {
		t.Error("Active complete session was cleaned up incorrectly (should use long timeout)")
	}
}

func TestHandshakeManager_MaxFramesLimit(t *testing.T) {
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	bssid := "00:11:22:33:44:55"
	station := "AA:BB:CC:DD:EE:FF"

	// Create a dummy EAPOL packet M1
	packetM1 := createEAPOLPacket(bssid, station, bssid, 1, 1)
	hm.ProcessFrame(packetM1)

	// Create M2 (RC=1)
	packetM2 := createEAPOLPacket(bssid, station, bssid, 2, 1)

	// Send 24 more packets (M2) to hit/exceed limit (Total 25)
	for i := 0; i < 24; i++ {
		// We need to ensure a session is created. ProcessFrame does that for EAPOL.
		hm.ProcessFrame(packetM2)
	}

	// Check frames in session
	// HandshakeManager uses lowercase MACs
	key := "00:11:22:33:44:55_aa:bb:cc:dd:ee:ff"
	hm.mu.RLock()
	session, exists := hm.sessions[key]
	hm.mu.RUnlock()

	if !exists {
		t.Fatal("Session not created")
	}

	if len(session.Frames) > maxFramesPerSession {
		t.Errorf("Session frames exceeded limit: got %d, max %d", len(session.Frames), maxFramesPerSession)
	}

	if len(session.Frames) != maxFramesPerSession {
		t.Errorf("Session frames should stop at limit: got %d, expected %d", len(session.Frames), maxFramesPerSession)
	}
}
