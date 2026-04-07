// Package channelstore handles persistence of per-interface channel configurations.
// Configurations are serialised as a JSON file at a path provided at construction time.
package channelstore

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ChannelConfig maps interface names to their assigned channel lists.
type ChannelConfig map[string][]int

// Store persists and retrieves channel configurations from a JSON file.
type Store struct {
	path string
}

// New returns a Store that reads/writes the file at path.
func New(path string) *Store {
	return &Store{path: path}
}

// Load reads the config file and returns the stored mapping.
// Returns an empty ChannelConfig (not nil) when the file does not exist.
func (s *Store) Load() (ChannelConfig, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(ChannelConfig), nil
		}
		return nil, err
	}
	var cfg ChannelConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save updates the channel list for a single interface and persists the full
// config back to disk atomically (write to tmp, rename).
func (s *Store) Save(iface string, channels []int) error {
	cfg, err := s.Load()
	if err != nil {
		cfg = make(ChannelConfig)
	}
	cfg[iface] = channels

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Write to a temp file then rename for atomic replacement.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
