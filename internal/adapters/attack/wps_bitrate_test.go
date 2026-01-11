package attack

import (
	"os"
	"os/exec"
	"testing"
)

// Mock (reuse helper process pattern)
func mockExecCommandTest(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcessBitrate", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestHelperProcessBitrate(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	if len(args) == 0 {
		return
	}

	cmd, cmdArgs := args[0], args[1:]

	if cmd == "iw" {
		// Validation logic same as sniffer
		foundLegacy5 := false
		for _, arg := range cmdArgs {
			if arg == "legacy-5" {
				foundLegacy5 = true
			}
		}
		if !foundLegacy5 {
			os.Stderr.WriteString("Missing legacy-5 argument in WPS optimization")
			os.Exit(1)
		}
	}
}

func TestWPSBitrateOptimization(t *testing.T) {
	// Swap execCommand
	oldExec := execCommand
	execCommand = mockExecCommandTest
	defer func() { execCommand = oldExec }()

	// Create engine (dummy registry is fine for this specific method test)
	engine := &WPSEngine{}

	// We can't call optimizeInterface directly if it's private (it is `optimizeInterface`)
	// We are in package attack, so we CAN call it.

	engine.optimizeInterface("wlan0")
}
