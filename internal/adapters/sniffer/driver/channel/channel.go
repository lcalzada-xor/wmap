// Package channel provides helpers to set the active WiFi channel on a
// wireless interface in monitor mode using the "iw" utility.
package channel

import (
	"context"
	"fmt"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
)

// Set calls "iw <iface> set channel <ch>" to tune the interface.
func Set(exec executor.CommandExecutor, iface string, ch int) error {
	if ch <= 0 {
		return fmt.Errorf("invalid channel: %d", ch)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.Execute(ctx, "iw", iface, "set", "channel", fmt.Sprintf("%d", ch))
	if err != nil {
		return fmt.Errorf("set channel %d on %s: %w (%s)", ch, iface, err, string(out))
	}
	return nil
}

// SetWithRetry calls Set up to maxRetries times with exponential back-off
// (100 ms × attempt number between attempts).
func SetWithRetry(exec executor.CommandExecutor, iface string, ch, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := Set(exec, iface, ch); err == nil {
			return nil
		} else {
			lastErr = err
			time.Sleep(100 * time.Millisecond * time.Duration(i+1))
		}
	}
	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}
