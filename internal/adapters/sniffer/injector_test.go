package sniffer

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInjector_SerializeAuthPacket(t *testing.T) {
	// We need an injector instance to call method, even if handle is nil
	// because method is (i *Injector).
	// But serializeAuthPacket likely doesn't use 'i' fields except maybe 'seq' if used?
	// It uses sequence 0 passed as arg.

	inj := &Injector{}

	targetMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	srcMAC := randomMAC()

	pkt, err := inj.serializeAuthPacket(targetMAC, srcMAC, 100)

	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(pkt) == 0 {
		t.Fatal("Packet is empty")
	}

	t.Logf("Generated Auth Packet: %d bytes", len(pkt))
}

func TestRandomMAC(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	mac := randomMAC()
	t.Logf("Random MAC: %s", mac.String())
	assert.Len(t, mac, 6)
	// Check locally administered bit (bit 1 of first byte is set?)
	// 0x02 = 0000 0010.
	assert.True(t, mac[0]&0x02 != 0)
}
