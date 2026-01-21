package wps

import (
	"context"
	"strings"
	"testing"
)

func TestWPSEngine_HealthCheck(t *testing.T) {
	// 1. Test with invalid paths (should fail)
	engine := NewWPSEngine(nil)
	engine.SetToolPaths("/non/existent/reaver", "/non/existent/pixiewps")

	err := engine.HealthCheck(context.Background())
	if err == nil {
		t.Error("HealthCheck() expected error for invalid paths, got nil")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("HealthCheck() error = %v, want 'not found'", err)
	}

	// 2. Test with valid paths (using standard unix tools as mock)
	// We use 'ls' as a dummy executable that should exist
	engine.SetToolPaths("ls", "ls")
	err = engine.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck() unexpected error with valid tools: %v", err)
	}
}
