package network

import (
	"context"
	"fmt"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/attack/authflood"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// AttackCoordinator manages all active network attacks.
type AttackCoordinator struct {
	registry        ports.DeviceRegistry
	sniffer         ports.Sniffer
	audit           ports.AuditService
	deauthEngine    ports.DeauthService
	wpsEngine       ports.WPSAttackService
	authFloodEngine *authflood.AuthFloodEngine
}

// NewAttackCoordinator creates a new attack coordinator.
func NewAttackCoordinator(
	registry ports.DeviceRegistry,
	sniffer ports.Sniffer,
	audit ports.AuditService,
) *AttackCoordinator {
	return &AttackCoordinator{
		registry: registry,
		sniffer:  sniffer,
		audit:    audit,
	}
}

// SetDeauthEngine sets the deauth engine.
func (c *AttackCoordinator) SetDeauthEngine(engine ports.DeauthService) {
	c.deauthEngine = engine
}

// SetWPSEngine sets the WPS engine.
func (c *AttackCoordinator) SetWPSEngine(engine ports.WPSAttackService) {
	c.wpsEngine = engine
}

// SetAuthFloodEngine sets the Auth Flood engine.
func (c *AttackCoordinator) SetAuthFloodEngine(engine *authflood.AuthFloodEngine) {
	c.authFloodEngine = engine
}

// StartDeauthAttack initiates a deauth attack with smart defaults.
func (c *AttackCoordinator) StartDeauthAttack(ctx context.Context, config domain.DeauthAttackConfig) (string, error) {
	ctx, span := otel.Tracer("network-service").Start(ctx, "StartDeauthAttack")
	defer span.End()

	span.SetAttributes(attribute.String("target.mac", config.TargetMAC))
	span.SetAttributes(attribute.String("attack.type", string(config.AttackType)))

	if c.deauthEngine == nil {
		return "", fmt.Errorf("deauth engine not initialized")
	}

	// Channel Auto-detection
	if config.Channel == 0 {
		device, exists := c.registry.GetDevice(ctx, config.TargetMAC)
		if exists && device.Channel > 0 {
			config.Channel = device.Channel
		} else {
			return "", fmt.Errorf("channel is 0 and could not be detected for %s", config.TargetMAC)
		}
	}

	// Interface Auto-detection
	if config.Interface == "" {
		if c.sniffer != nil {
			interfaces, _ := c.sniffer.GetInterfaces(ctx)
			if len(interfaces) > 0 {
				found := false
				for _, iface := range interfaces {
					chans, _ := c.sniffer.GetInterfaceChannels(ctx, iface)
					for _, ch := range chans {
						if ch == config.Channel {
							config.Interface = iface
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					config.Interface = interfaces[0]
				}
			}
		}
	}

	// Smart Targeting Logic
	if config.AttackType == domain.DeauthBroadcast {
		// Find clients connected to this AP
		devices := c.registry.GetAllDevices(ctx)
		var bestClient string
		var bestLastSeen time.Time

		for _, d := range devices {
			if d.ConnectedSSID == config.TargetMAC && d.Type == "station" {
				if d.LastPacketTime.After(bestLastSeen) {
					bestClient = d.MAC
					bestLastSeen = d.LastPacketTime
				}
			}
		}

		if bestClient != "" {
			config.AttackType = domain.DeauthTargeted
			config.ClientMAC = bestClient
			if c.audit != nil {
				c.audit.Log(ctx, domain.ActionInfo, config.TargetMAC, fmt.Sprintf("Smart Targeting: Upgraded Broadcast -> Targeted (Client: %s)", bestClient))
			}
			span.AddEvent("Smart Targeting Upgraded")
		}
	}

	id, err := c.deauthEngine.StartAttack(ctx, config)
	if err == nil && c.audit != nil {
		c.audit.Log(ctx, domain.ActionDeauthStart, config.TargetMAC, fmt.Sprintf("Type: %s, Ch: %d", config.AttackType, config.Channel))
	} else if err != nil {
		span.RecordError(err)
	}
	return id, err
}

// StopDeauthAttack stops a running deauth attack.
func (c *AttackCoordinator) StopDeauthAttack(ctx context.Context, id string, force bool) error {
	if c.deauthEngine == nil {
		return fmt.Errorf("deauth engine not initialized")
	}
	err := c.deauthEngine.StopAttack(ctx, id, force)
	if err == nil && c.audit != nil {
		msg := "Attack stopped by user"
		if force {
			msg += " (forced)"
		}
		c.audit.Log(ctx, domain.ActionDeauthStop, id, msg)
	}
	return err
}

// GetDeauthStatus returns status of a deauth attack.
func (c *AttackCoordinator) GetDeauthStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error) {
	if c.deauthEngine == nil {
		return domain.DeauthAttackStatus{}, fmt.Errorf("deauth engine not initialized")
	}
	return c.deauthEngine.GetAttackStatus(ctx, id)
}

// ListDeauthAttacks lists active deauth attacks.
func (c *AttackCoordinator) ListDeauthAttacks(ctx context.Context) []domain.DeauthAttackStatus {
	if c.deauthEngine == nil {
		return []domain.DeauthAttackStatus{}
	}
	return c.deauthEngine.ListActiveAttacks(ctx)
}

// StartWPSAttack initiates a WPS Pixie Dust attack.
func (c *AttackCoordinator) StartWPSAttack(ctx context.Context, config domain.WPSAttackConfig) (string, error) {
	if c.wpsEngine == nil {
		return "", fmt.Errorf("WPS engine not initialized")
	}
	if config.TargetBSSID == "" {
		return "", fmt.Errorf("target BSSID is required")
	}

	// Auto-detect channel
	if config.Channel == 0 {
		device, exists := c.registry.GetDevice(ctx, config.TargetBSSID)
		if exists && device.Channel > 0 {
			config.Channel = device.Channel
		} else {
			return "", fmt.Errorf("channel is 0 and could not be detected for %s", config.TargetBSSID)
		}
	}

	// Auto-detect interface
	if config.Interface == "" {
		if c.sniffer != nil {
			interfaces, _ := c.sniffer.GetInterfaces(ctx)
			if len(interfaces) > 0 {
				config.Interface = interfaces[0]
			} else {
				return "", fmt.Errorf("no interfaces available")
			}
		} else {
			return "", fmt.Errorf("sniffer not initialized")
		}
	}

	return c.wpsEngine.StartAttack(ctx, config)
}

// StopWPSAttack stops a WPS attack.
func (c *AttackCoordinator) StopWPSAttack(ctx context.Context, id string, force bool) error {
	if c.wpsEngine == nil {
		return fmt.Errorf("WPS engine not initialized")
	}
	return c.wpsEngine.StopAttack(ctx, id, force)
}

// GetWPSStatus returns status of a WPS attack.
func (c *AttackCoordinator) GetWPSStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error) {
	if c.wpsEngine == nil {
		return domain.WPSAttackStatus{}, fmt.Errorf("WPS engine not initialized")
	}
	return c.wpsEngine.GetStatus(ctx, id)
}

// StartAuthFloodAttack initiates an Auth Flood attack.
func (c *AttackCoordinator) StartAuthFloodAttack(ctx context.Context, config domain.AuthFloodAttackConfig) (string, error) {
	if c.authFloodEngine == nil {
		return "", fmt.Errorf("auth flood engine not initialized")
	}

	if config.Channel == 0 && config.TargetBSSID != "" {
		device, exists := c.registry.GetDevice(ctx, config.TargetBSSID)
		if exists && device.Channel > 0 {
			config.Channel = device.Channel
		}
	}

	if config.Interface == "" && c.sniffer != nil {
		interfaces, _ := c.sniffer.GetInterfaces(ctx)
		if len(interfaces) > 0 {
			config.Interface = interfaces[0]
		}
	}

	id, err := c.authFloodEngine.StartAttack(ctx, config)
	if err == nil && c.audit != nil {
		c.audit.Log(ctx, domain.ActionDeauthStart, config.TargetBSSID, "Started Auth Flood")
	}
	return id, err
}

// StopAuthFloodAttack stops an Auth Flood attack.
func (c *AttackCoordinator) StopAuthFloodAttack(ctx context.Context, id string, force bool) error {
	if c.authFloodEngine == nil {
		return fmt.Errorf("auth flood engine not initialized")
	}
	return c.authFloodEngine.StopAttack(ctx, id, force)
}

// GetAuthFloodStatus returns status of an Auth Flood attack.
func (c *AttackCoordinator) GetAuthFloodStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error) {
	if c.authFloodEngine == nil {
		return domain.AuthFloodAttackStatus{}, fmt.Errorf("auth flood engine not initialized")
	}
	return c.authFloodEngine.GetStatus(ctx, id)
}

// StopAll stops all active attacks.
func (c *AttackCoordinator) StopAll(ctx context.Context) {
	if c.deauthEngine != nil {
		c.deauthEngine.StopAll(ctx)
	}
	if c.wpsEngine != nil {
		c.wpsEngine.StopAll(ctx)
	}
	if c.authFloodEngine != nil {
		c.authFloodEngine.StopAll(ctx)
	}
}
