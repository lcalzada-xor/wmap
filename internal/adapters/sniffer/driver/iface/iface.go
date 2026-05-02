// Package iface provides read-only queries about a wireless interface's
// current state: operating mode, TX power, and kernel driver name.
package iface

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
)

// Config holds the runtime state of a wireless interface.
type Config struct {
	Mode    string
	TxPower int // dBm
}

// GetCurrentConfig queries "iw dev <iface> info" and returns the current
// operating mode and TX-power for the interface.
func GetCurrentConfig(exec executor.CommandExecutor, iface string) (Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.Execute(ctx, "iw", "dev", iface, "info")
	if err != nil {
		return Config{Mode: "unknown"}, fmt.Errorf("iw dev %s info: %w", iface, err)
	}

	cfg := Config{Mode: "unknown"}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "type "):
			cfg.Mode = strings.TrimPrefix(line, "type ")
		case strings.HasPrefix(line, "txpower "):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if val, convErr := strconv.ParseFloat(parts[1], 64); convErr == nil {
					cfg.TxPower = int(val)
				}
			}
		}
	}
	return cfg, nil
}

// GetPhy returns the underlying PHY name (e.g. "phy0") for iface.
func GetPhy(exec executor.CommandExecutor, iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.Execute(ctx, "iw", "dev", iface, "info")
	if err != nil {
		return "", fmt.Errorf("iw dev %s info: %w", iface, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "wiphy ") {
			// "wiphy 0" → "phy0"
			num := strings.TrimPrefix(line, "wiphy ")
			return "phy" + strings.TrimSpace(num), nil
		}
	}
	return "", fmt.Errorf("could not find wiphy for %s", iface)
}

// GetDriverName reads the kernel driver name for iface via ethtool.
func GetDriverName(exec executor.CommandExecutor, iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.Execute(ctx, "ethtool", "-i", iface)
	if err != nil {
		return "", fmt.Errorf("ethtool -i %s: %w", iface, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "driver:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "driver:")), nil
		}
	}
	return "unknown", nil
}
