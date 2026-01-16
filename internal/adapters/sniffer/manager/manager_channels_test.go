package sniffer

import (
	"reflect"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/hopping"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
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
		got := m.GetInterfaces()
		want := []string{"wlan0", "wlan1"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetInterfaces() = %v, want %v", got, want)
		}
	})

	// Test GetInterfaceChannels
	t.Run("GetInterfaceChannels", func(t *testing.T) {
		got := m.GetInterfaceChannels("wlan0")
		want := []int{1, 6}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetInterfaceChannels(wlan0) = %v, want %v", got, want)
		}

		got = m.GetInterfaceChannels("wlan1")
		want = []int{36, 40}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetInterfaceChannels(wlan1) = %v, want %v", got, want)
		}

		got = m.GetInterfaceChannels("wlan99") // Missing
		if len(got) != 0 {
			t.Errorf("GetInterfaceChannels(wlan99) = %v, want []", got)
		}
	})

	// Test SetInterfaceChannels
	t.Run("SetInterfaceChannels", func(t *testing.T) {
		newChans := []int{11}
		m.SetInterfaceChannels("wlan0", newChans)

		got := m.GetInterfaceChannels("wlan0")
		if !reflect.DeepEqual(got, newChans) {
			t.Errorf("SetInterfaceChannels failed. Got %v, want %v", got, newChans)
		}

		// Ensure wlan1 is untouched
		got1 := m.GetInterfaceChannels("wlan1")
		want1 := []int{36, 40}
		if !reflect.DeepEqual(got1, want1) {
			t.Errorf("Side effect on wlan1. Got %v, want %v", got1, want1)
		}
	})
}
