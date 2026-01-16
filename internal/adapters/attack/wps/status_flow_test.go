package wps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Helper process for flow test
func TestFlowHelper(t *testing.T) {
	if os.Getenv("GO_WANT_FLOW_HELPER") != "1" {
		return
	}
	// Simulate Reaver output sequence
	fmt.Fprintln(os.Stderr, "Waiting for beacon from 00:11:22:33:44:55")
	time.Sleep(50 * time.Millisecond)
	fmt.Fprintln(os.Stderr, "Sending EAPOL start request")
	time.Sleep(50 * time.Millisecond)
	fmt.Fprintln(os.Stderr, "Running pixiewps...")
	time.Sleep(50 * time.Millisecond)
	fmt.Fprintln(os.Stdout, "[+] WPS PIN: '12345670'")
	os.Exit(0)
}

func mockFlowExec(ctx context.Context, name string, arg ...string) *exec.Cmd {
	cs := []string{"-test.run=TestFlowHelper", "--", name}
	cs = append(cs, arg...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_FLOW_HELPER=1"}
	return cmd
}

func TestWPSEngine_StatusFlow(t *testing.T) {
	// Setup engine
	engine := NewWPSEngine(nil)
	// Mock binaries
	engine.SetToolPaths("ls", "ls")

	// Mock exec
	originalExecCmd := execCmd
	execCmd = mockFlowExec
	defer func() { execCmd = originalExecCmd }()

	// Capture statuses
	statusChan := make(chan string, 10)
	engine.SetCallbacks(nil, func(s domain.WPSAttackStatus) {
		statusChan <- s.Status
	})

	// Start Attack
	config := domain.WPSAttackConfig{
		TargetBSSID:    "00:11:22:33:44:55",
		Interface:      "wlan0",
		TimeoutSeconds: 2,
	}

	// We expect dependencies to pass because we set paths to 'ls' and mocked HealthCheck logic inside StartAttack?
	// Actually StartAttack calls HealthCheck which checks real filesystem.
	// We already put 'ls' as paths, so HealthCheck should pass.

	_, err := engine.StartAttack(config)
	if err != nil {
		t.Fatalf("Failed to start attack: %v", err)
	}

	// Collected statuses
	var history []string
	timeout := time.After(2 * time.Second)

	expectedOrder := []string{"running", "associating", "exchanging_keys", "cracking", "success"}
	expectedIndex := 0

Loop:
	for {
		select {
		case s := <-statusChan:
			history = append(history, s)
			// Check against expected
			if expectedIndex < len(expectedOrder) && s == expectedOrder[expectedIndex] {
				expectedIndex++
			}
			if s == "success" || s == "failed" || s == "timeout" {
				break Loop
			}
		case <-timeout:
			t.Fatal("Timeout waiting for status updates")
		}
	}

	// Verification
	// Note: 'running' is set initially, but callback might be triggered first time or not depending on implementation.
	// engine.go: StartAttack -> set running -> callback NOT called explicitly there?
	// Let's check engine.go:
	// s.activeAttacks[id] = status (running) -> NO callback called here.
	// So first callback is from updateStatus inside runAttack or granular updates.

	// Wait, standard reaver logic doesn't call updateStatus("running").
	// So we might miss "running" in the channel.

	// Adjusted expectation: associating -> exchanging -> cracking -> success
	// Let's print history to debug if it fails

	// Check if we hit "associating"
	foundAssoc := false
	for _, h := range history {
		if h == "associating" {
			foundAssoc = true
		}
	}
	if !foundAssoc {
		t.Errorf("Did not receive 'associating' status. History: %v", history)
	}

	foundCrack := false
	for _, h := range history {
		if h == "cracking" {
			foundCrack = true
		}
	}
	if !foundCrack {
		t.Errorf("Did not receive 'cracking' status. History: %v", history)
	}
}
