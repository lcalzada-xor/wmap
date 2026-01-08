package sniffer

import (
	"testing"
	"time"
)

func TestHandshakeManager_CleanupSessions(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	// Manually inject a session
	now := time.Now()
	expiredTime := now.Add(-10 * time.Minute) // Older than default 5 min timeout
	activeTime := now.Add(-1 * time.Minute)   // Recent

	hm.sessions["expired_session"] = &HandshakeSession{
		BSSID:      "00:11:22:33:44:55",
		StationMAC: "AA:BB:CC:DD:EE:FF",
		LastUpdate: expiredTime,
	}

	hm.sessions["active_session"] = &HandshakeSession{
		BSSID:      "00:11:22:33:44:55",
		StationMAC: "11:22:33:44:55:66",
		LastUpdate: activeTime,
	}

	// Run cleanup
	hm.CleanupSessions()

	// Verify
	if _, exists := hm.sessions["expired_session"]; exists {
		t.Error("Expired session was not cleaned up")
	}

	if _, exists := hm.sessions["active_session"]; !exists {
		t.Error("Active session was incorrectly cleaned up")
	}
}

func TestHandshakeManager_MaxFramesLimit(t *testing.T) {
	tmpDir := t.TempDir()
	hm := NewHandshakeManager(tmpDir)

	bssid := "00:11:22:33:44:55"
	station := "AA:BB:CC:DD:EE:FF"

	// Create a dummy EAPOL packet using helper from handshake_manager_test.go
	packet := createEAPOLPacket(bssid, station, bssid, 1)

	// Send 25 packets
	for i := 0; i < 25; i++ {
		// We need to ensure a session is created. ProcessFrame does that for EAPOL.
		hm.ProcessFrame(packet)
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
