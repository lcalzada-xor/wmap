package injection

import "sync"

// MockInjector implements PacketInjector for testing purposes.
// It captures injected packets in memory instead of sending them to a network interface.
type MockInjector struct {
	mu         sync.Mutex
	ReqPackets [][]byte
	Closed     bool
}

// NewMockInjector creates a new instance of MockInjector.
func NewMockInjector() *MockInjector {
	return &MockInjector{
		ReqPackets: make([][]byte, 0),
	}
}

// Inject stores the packet in the ReqPackets slice.
func (m *MockInjector) Inject(packet []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Copy buffer to avoid reference issues if the caller reuses the buffer
	p := make([]byte, len(packet))
	copy(p, packet)

	m.ReqPackets = append(m.ReqPackets, p)
	return nil
}

// Close marks the injector as closed.
func (m *MockInjector) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Closed = true
}

// GetPackets returns a copy of the captured packets.
func (m *MockInjector) GetPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	packets := make([][]byte, len(m.ReqPackets))
	for i, p := range m.ReqPackets {
		packets[i] = make([]byte, len(p))
		copy(packets[i], p)
	}
	return packets
}

// ClearPackets clears the captured packets buffer.
func (m *MockInjector) ClearPackets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReqPackets = make([][]byte, 0)
}
