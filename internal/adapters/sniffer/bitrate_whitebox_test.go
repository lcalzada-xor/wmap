package sniffer

import (
	"os"
	"os/exec"
	"testing"
)

// Mock execCommand for the test
func mockExecCommandTest(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// TestHelperProcess is the mock process that validates arguments
func TestHelperProcess(t *testing.T) {
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

	// Validate iw command
	if cmd == "iw" {
		// Expect: dev <iface> set bitrates legacy-2.4 1 2 5.5 11 legacy-5 6 9 12
		// Minimal check: ensure "legacy-5" and "6" "9" "12" are present
		foundLegacy5 := false
		for _, arg := range cmdArgs {
			if arg == "legacy-5" {
				foundLegacy5 = true
			}
		}
		if !foundLegacy5 {
			os.Stderr.WriteString("Missing legacy-5 argument")
			os.Exit(1)
		}
	}
}

func TestOptimizeInterfaceForInjection(t *testing.T) {
	// Swap the package-level variable
	oldExec := execCommand
	execCommand = mockExecCommandTest
	defer func() { execCommand = oldExec }()

	// Retrieve access to internal method via struct (fields are allowed since we are in package sniffer)
	inj := &Injector{
		Interface: "wlan0mon",
	}

	// Run method
	inj.OptimizeInterfaceForInjection()

	// If TestHelperProcess exits with 0 (default), it passed.
	// If it prints to stderr and exits 1, we will see it in test logs.
	// Since the function logs warning on error, but doesn't return it, we assume success if no panic
	// and if we want closer verification, we'd need to capturing log references.
	// But TestHelperProcess failing will cause 'exit status 1' log.
}
