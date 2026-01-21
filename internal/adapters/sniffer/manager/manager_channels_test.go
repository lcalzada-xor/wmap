package manager

import (
	"context"
	"reflect"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/hopping"
)

func TestManagerChannels(t *testing.T) {
	// Setup Manager with manual sniffers
	m := &SnifferManager{
		Interfaces: []string{"wlan0", "wlan1"},
	}

	// Create dummy sniffers with hoppers
	// Note: We don't start them, so no exec.Command calls happen
	s0 := &capture.Sniffer{
		Config: capture.SnifferConfig{Interface: "wlan0"},
		Hopper: &hopping.ChannelHopper{Channels: []int{1, 6}},
	}
	s1 := &capture.Sniffer{
		Config: capture.SnifferConfig{Interface: "wlan1"},
		Hopper: &hopping.ChannelHopper{Channels: []int{36, 40}},
	}
	m.Sniffers = []*capture.Sniffer{s0, s1}

	// Test GetInterfaces
	t.Run("GetInterfaces", func(t *testing.T) {
		got, err := m.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces failed: %v", err)
		}
		want := []string{"wlan0", "wlan1"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetInterfaces() = %v, want %v", got, want)
		}
	})

	// Test GetInterfaceChannels
	t.Run("GetInterfaceChannels", func(t *testing.T) {
		got, err := m.GetInterfaceChannels(context.Background(), "wlan0")
		if err != nil {
			t.Fatalf("GetInterfaceChannels failed: %v", err)
		}
		want := []int{1, 6}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetInterfaceChannels(wlan0) = %v, want %v", got, want)
		}

		got, err = m.GetInterfaceChannels(context.Background(), "wlan1")
		if err != nil {
			t.Fatalf("GetInterfaceChannels failed: %v", err)
		}
		want = []int{36, 40}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetInterfaceChannels(wlan1) = %v, want %v", got, want)
		}

		got, _ = m.GetInterfaceChannels(context.Background(), "wlan99") // Missing
		if len(got) != 0 {
			t.Errorf("GetInterfaceChannels(wlan99) = %v, want []", got)
		}
	})

	// Test SetInterfaceChannels
	t.Run("SetInterfaceChannels", func(t *testing.T) {
		newChans := []int{11}
		m.SetInterfaceChannels(context.Background(), "wlan0", newChans)

		got, err := m.GetInterfaceChannels(context.Background(), "wlan0")
		if err != nil {
			t.Fatalf("GetInterfaceChannels failed: %v", err)
		}
		if !reflect.DeepEqual(got, newChans) {
			t.Errorf("SetInterfaceChannels failed. Got %v, want %v", got, newChans)
		}

		// Ensure wlan1 is untouched
		got1, err := m.GetInterfaceChannels(context.Background(), "wlan1")
		if err != nil {
			t.Fatalf("GetInterfaceChannels failed: %v", err)
		}
		want1 := []int{36, 40}
		if !reflect.DeepEqual(got1, want1) {
			t.Errorf("Side effect on wlan1. Got %v, want %v", got1, want1)
		}
	})
}
