package injection

// PacketInjector defines the interface for injecting packets
type PacketInjector interface {
	Inject(packet []byte) error
	Close()
}
