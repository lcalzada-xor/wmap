package config

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds all application configuration.
type Config struct {
	Interfaces   []string
	Addr         string
	MockMode     bool
	DBPath       string
	PcapPath     string
	GRPCPort     int
	Debug        bool
	DwellTime    int // in milliseconds
	WorkspaceDir      string
	HandshakeDir      string
	ChannelConfigPath string
	BaseDir           string
}

// Load parses command line flags and environment variables to populate Config.
// Flags take precedence over environment variables.
func Load() *Config {
	cfg := &Config{}

	// 1. Base Directory Setup
	defaultBase := getEnv("WMAP_DIR", getDefaultBaseDir())
	flag.StringVar(&cfg.BaseDir, "dir", defaultBase, "Base directory for all WMAP data (~/.wmap)")

	// 2. Other Configuration flags
	ifaceStr := getEnv("WMAP_INTERFACE", "wlan0")
	cfg.Addr = getEnv("WMAP_ADDR", ":8080")
	cfg.MockMode = getEnvBool("WMAP_MOCK", false)
	cfg.GRPCPort = int(getEnvFloat("WMAP_GRPC", 9000))

	flag.StringVar(&ifaceStr, "i", ifaceStr, "Network interface(s) in monitor mode (comma separated)")
	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "HTTP server address")
	flag.BoolVar(&cfg.MockMode, "mock", cfg.MockMode, "Run in mock mode (simulation)")
	flag.IntVar(&cfg.GRPCPort, "grpc", cfg.GRPCPort, "gRPC Server Port")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable verbose debug logging")
	flag.IntVar(&cfg.DwellTime, "dwell", 300, "Channel dwell time in milliseconds")
	flag.StringVar(&cfg.PcapPath, "pcap", "", "Path to save PCAP file (empty to disable)")

	flag.Parse()

	// 3. Resolve static paths relative to BaseDir (after flag.Parse)
	cfg.DBPath = filepath.Join(cfg.BaseDir, "wmap.db")
	cfg.WorkspaceDir = filepath.Join(cfg.BaseDir, "workspaces")
	cfg.HandshakeDir = filepath.Join(cfg.BaseDir, "handshakes")
	cfg.ChannelConfigPath = filepath.Join(cfg.BaseDir, "channels.json")

	// Parse interfaces
	cfg.Interfaces = parseInterfaces(ifaceStr)

	return cfg
}

func parseInterfaces(s string) []string {
	var ifaces []string
	if s == "" {
		return ifaces
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			ifaces = append(ifaces, trimmed)
		}
	}
	return ifaces
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if value, ok := os.LookupEnv(key); ok {
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return fallback
}

// getDefaultBaseDir returns the default base directory in user's home directory.
func getDefaultBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not get user home directory, using current dir: %v", err)
		return ".wmap"
	}

	return filepath.Join(home, ".wmap")
}
