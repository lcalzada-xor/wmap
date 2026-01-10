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
	Latitude     float64
	Longitude    float64
	MockMode     bool
	DBPath       string
	PcapPath     string
	GRPCPort     int
	Debug        bool
	DwellTime    int // in milliseconds
	ReaverPath   string
	PixiewpsPath string
}

// Load parses command line flags and environment variables to populate Config.
// Flags take precedence over environment variables.
func Load() *Config {
	cfg := &Config{}

	// Defaults and Environment Variables
	ifaceStr := getEnv("WMAP_INTERFACE", "wlan0")
	cfg.Addr = getEnv("WMAP_ADDR", ":8080")
	cfg.Latitude = getEnvFloat("WMAP_LAT", 40.4168)
	cfg.Longitude = getEnvFloat("WMAP_LNG", -3.7038)
	cfg.MockMode = getEnvBool("WMAP_MOCK", false)
	cfg.DBPath = getEnv("WMAP_DB", getDefaultDBPath())
	cfg.GRPCPort = int(getEnvFloat("WMAP_GRPC", 9000))

	// Command Line Flags (Override Env)
	flag.StringVar(&ifaceStr, "i", ifaceStr, "Network interface(s) in monitor mode (comma separated)")
	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "HTTP server address")
	flag.Float64Var(&cfg.Latitude, "lat", cfg.Latitude, "Static Latitude")
	flag.Float64Var(&cfg.Longitude, "lng", cfg.Longitude, "Static Longitude")
	flag.BoolVar(&cfg.MockMode, "mock", cfg.MockMode, "Run in mock mode (simulation)")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "Path to SQLite database")
	flag.StringVar(&cfg.PcapPath, "pcap", "", "Path to save PCAP file (empty to disable)")
	flag.IntVar(&cfg.GRPCPort, "grpc", cfg.GRPCPort, "gRPC Server Port")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable verbose debug logging")
	flag.IntVar(&cfg.DwellTime, "dwell", 300, "Channel dwell time in milliseconds")
	flag.StringVar(&cfg.ReaverPath, "reaver-path", "reaver", "Path to reaver binary")
	flag.StringVar(&cfg.PixiewpsPath, "pixiewps-path", "pixiewps", "Path to pixiewps binary")

	flag.Parse()

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

// getDefaultDBPath returns the default database path in user's home directory.
// Creates the directory if it doesn't exist.
func getDefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not get user home directory, using current dir: %v", err)
		return "wmap.db"
	}

	// Use ~/.wmap directory
	wmapDir := filepath.Join(home, ".wmap")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(wmapDir, 0755); err != nil {
		log.Printf("Warning: Could not create .wmap directory, using current dir: %v", err)
		return "wmap.db"
	}

	return filepath.Join(wmapDir, "wmap.db")
}
