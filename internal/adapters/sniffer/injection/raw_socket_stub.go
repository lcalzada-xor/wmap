//go:build !linux

package injection

import "fmt"

func NewRawInjector(iface string) (PacketInjector, error) {
	return nil, fmt.Errorf("raw injection only supported on linux")
}
