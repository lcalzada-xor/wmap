package geo

// Location represents a geographic coordinate.
type Location struct {
	Latitude  float64
	Longitude float64
}

// Provider defines the interface for obtaining the current location.
type Provider interface {
	GetLocation() Location
}

// StaticProvider implements Provider with a fixed location.
type StaticProvider struct {
	Lat float64
	Lng float64
}

// NewStaticProvider creates a provider that always returns the same location.
func NewStaticProvider(lat, lng float64) *StaticProvider {
	return &StaticProvider{
		Lat: lat,
		Lng: lng,
	}
}

// GetLocation returns the fixed location.
func (s *StaticProvider) GetLocation() Location {
	return Location{
		Latitude:  s.Lat,
		Longitude: s.Lng,
	}
}
