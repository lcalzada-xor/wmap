package wps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Mock for iw dev
func mockIwDev(ctx context.Context, name string, arg ...string) *exec.Cmd {
	cs := []string{"-test.run=TestIwDevHelper", "--", name}
	cs = append(cs, arg...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_IW_HELPER=1"}
	return cmd
}

func TestIwDevHelper(t *testing.T) {
	if os.Getenv("GO_WANT_IW_HELPER") != "1" {
		return
	}
	// Simulate "iw dev" output
	fmt.Println(`phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 00:11:22:33:44:55
		type managed
		txpower 20.00 dBm
	Interface wlan1mon
		ifindex 4
		wdev 0x2
		addr 66:77:88:99:aa:bb
		type monitor
		txpower 20.00 dBm`)
	os.Exit(0)
}

func TestWPSEngine_DetectMonitorInterface(t *testing.T) {
	engine := NewWPSEngine(nil)

	// Mock execCmd
	originalExecCmd := execCommand
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return mockIwDev(context.Background(), name, arg...)
	}
	defer func() { execCommand = originalExecCmd }()

	iface, err := engine.detectMonitorInterface()
	if err != nil {
		t.Fatalf("detectMonitorInterface() error = %v", err)
	}

	if iface != "wlan1mon" {
		t.Errorf("expected wlan1mon, got %s", iface)
	}
}
