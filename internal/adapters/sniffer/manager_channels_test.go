package sniffer

import (
	"context"
	"reflect"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/channelstore"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/hopping"
)

func TestManagerChannels(t *testing.T) {
	s0 := &Sniffer{
		Config: SnifferConfig{Interface: "wlan0"},
		Hopper: &hopping.ChannelHopper{Channels: []int{1, 6}},
	}
	s1 := &Sniffer{
		Config: SnifferConfig{Interface: "wlan1"},
		Hopper: &hopping.ChannelHopper{Channels: []int{36, 40}},
	}

	// Manager backed by real sniffers in its map but without starting them.
	m := &SnifferManager{
		Interfaces:   []string{"wlan0", "wlan1"},
		sniffers:     map[string]*Sniffer{"wlan0": s0, "wlan1": s1},
		channelStore: channelstore.New(t.TempDir() + "/channels.json"),
	}

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

	t.Run("GetInterfaceChannels", func(t *testing.T) {
		got, err := m.GetInterfaceChannels(context.Background(), "wlan0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, []int{1, 6}) {
			t.Errorf("GetInterfaceChannels(wlan0) = %v, want [1 6]", got)
		}

		got, err = m.GetInterfaceChannels(context.Background(), "wlan1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, []int{36, 40}) {
			t.Errorf("GetInterfaceChannels(wlan1) = %v, want [36 40]", got)
		}

		got, _ = m.GetInterfaceChannels(context.Background(), "wlan99")
		if len(got) != 0 {
			t.Errorf("GetInterfaceChannels(wlan99) = %v, want []", got)
		}
	})

	t.Run("SetInterfaceChannels", func(t *testing.T) {
		newChans := []int{11}
		m.SetInterfaceChannels(context.Background(), "wlan0", newChans)

		got, err := m.GetInterfaceChannels(context.Background(), "wlan0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, newChans) {
			t.Errorf("SetInterfaceChannels: got %v, want %v", got, newChans)
		}

		// wlan1 must be untouched.
		got1, _ := m.GetInterfaceChannels(context.Background(), "wlan1")
		if !reflect.DeepEqual(got1, []int{36, 40}) {
			t.Errorf("side-effect on wlan1: got %v, want [36 40]", got1)
		}
	})
}
