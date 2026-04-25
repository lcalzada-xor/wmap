// Package executor provides the CommandExecutor abstraction used by all
// wireless driver sub-packages to run system commands (iw, ip, systemctl…).
// Keeping it in its own package breaks the import cycle between sub-packages
// that need the interface and those that implement it.
package executor

import (
	"context"
	"os/exec"
)

// CommandExecutor abstracts system command execution so every sub-package can
// be tested without real system calls.
type CommandExecutor interface {
	Execute(ctx context.Context, name string, args ...string) ([]byte, error)
}

// System is the production CommandExecutor that delegates to os/exec.
type System struct{}

// Execute runs name with args and returns combined stdout+stderr output.
func (System) Execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
