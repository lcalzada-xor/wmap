package web

// Re-export types from subpackages for backward compatibility
import (
	websocket "github.com/lcalzada-xor/wmap/internal/adapters/web/websocket"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// WSManager is re-exported from the websocket subpackage
type WSManager = websocket.WSManager

// NewWSManager creates a new WSManager
func NewWSManager(service ports.NetworkService) *WSManager {
	return websocket.NewWSManager(service)
}
