package storage

import (
	"context"
	"log"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// SQLiteAdapter implements ports.Storage using GORM and SQLite.
type SQLiteAdapter struct {
	db *gorm.DB
}

// DeviceModel is the GORM model for devices.
type DeviceModel struct {
	MAC            string `gorm:"primaryKey"`
	Type           string
	Vendor         string
	RSSI           int
	SSID           string `gorm:"column:ssid"`
	Channel        int
	Crypto         string
	Security       string // WPA2, WPA3, OPEN, WEP
	Standard       string // 802.11ax (WiFi 6), etc.
	Frequency      int    // 2412, 5180, etc.
	ChannelWidth   int    // 20, 40, 80, 160 MHz
	WPSInfo        string // Configured, Unconfigured
	LastPacketTime time.Time
	FirstSeen      time.Time
	LastSeen       time.Time
	ConnectedSSID  string
	Model          string
	OS             string
	IsRandomized   bool
	IsWiFi6        bool
	IsWiFi7        bool
	Signature      string
	Has11k         bool
	Has11v         bool
	Has11r         bool

	// Traffic Statistics
	DataTransmitted int64
	DataReceived    int64
	PacketsCount    int
	RetryCount      int

	// Connection State (Logic 2.0)
	ConnectionState  string
	ConnectionTarget string
	ConnectionError  string

	// Security & Cracking (New Fields)
	HasHandshake      bool
	HandshakeFile     string
	EncryptionDetails string // JSON encoded RSNInfo
	WPSData           string // JSON encoded WPSDetails
	IEFingerprint     string

	// --- Missing Persistent Capabilities & Fingerprinting Fields ---
	Capabilities     string  // JSON encoded []string
	MobilityDomain   string  // JSON encoded MobilityDomain
	BSSLoad          string  // JSON encoded BSSLoad
	ObservedSSIDs    string  // JSON encoded []string
	LastANonce       string
	IETags           string  // JSON encoded []int
	ProbeHash        string
	ManufacturerRaw  string
	VendorConfidence float32

	// ProbedSSIDs is a many-to-many or one-to-many relationship,
	// but for simplicity in SQLite we can store it in a separate table.
	ProbedSSIDs []ProbeModel `gorm:"foreignKey:DeviceMAC"`
}

// ProbeModel stores SSIDs probed by a device.
type ProbeModel struct {
	ID        uint   `gorm:"primaryKey"`
	DeviceMAC string `gorm:"uniqueIndex:idx_mac_ssid"`
	SSID      string `gorm:"column:ssid;uniqueIndex:idx_mac_ssid"`
	LastSeen  time.Time
}

// ConnectionEventModel stores history of connection states.
type ConnectionEventModel struct {
	ID        uint   `gorm:"primaryKey"`
	DeviceMAC string `gorm:"index"`
	EventType string `gorm:"index"`
	TargetMAC string
	Timestamp time.Time `gorm:"index"` // Ordered history
	Reason    int
}

// NewSQLiteAdapter initializes the database and migrates schema.
func NewSQLiteAdapter(path string) (*SQLiteAdapter, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&DeviceModel{}, &ProbeModel{}, &ConnectionEventModel{}); err != nil {
		return nil, err
	}

	// Performance & Concurrency Optimizations
	// WAL mode allows simultaneous readers and one writer
	db.Exec("PRAGMA journal_mode=WAL;")
	// Busy timeout prevents "database locked" errors by waiting
	db.Exec("PRAGMA busy_timeout=5000;")
	// Synchronous NORMAL is faster and safe enough for WAL
	db.Exec("PRAGMA synchronous=NORMAL;")

	// Create Indices for Performance
	db.Exec("CREATE INDEX IF NOT EXISTS idx_devices_security ON device_models(security)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_conn_history_mac_time ON connection_event_models(device_mac, timestamp)")

	return &SQLiteAdapter{db: db}, nil
}

// SaveDevice saves or updates a device and its probes inside a transaction.
func (a *SQLiteAdapter) SaveDevice(ctx context.Context, d domain.Device) error {
	// Convert domain.Device to DeviceModel
	model := toModel(d)

	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Upsert Device
		// On conflict (MAC), update all fields.
		if err := tx.Save(&model).Error; err != nil {
			return err
		}

		// Save Probed SSIDs
		if len(d.ProbedSSIDs) > 0 {
			var probes []ProbeModel
			for ssid, ts := range d.ProbedSSIDs {
				probes = append(probes, ProbeModel{
					DeviceMAC: d.MAC,
					SSID:      ssid,
					LastSeen:  ts,
				})
			}
			err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "device_mac"}, {Name: "ssid"}},
				DoUpdates: clause.AssignmentColumns([]string{"last_seen"}),
			}).Create(&probes).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// SaveDevicesBatch saves multiple devices in a single transaction.
func (a *SQLiteAdapter) SaveDevicesBatch(ctx context.Context, devices []domain.Device) error {
	if len(devices) == 0 {
		return nil
	}

	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var allProbes []ProbeModel

		for _, d := range devices {
			model := toModel(d)

			// Upsert device
			if err := tx.Save(&model).Error; err != nil {
				return err
			}

			// Track ProbedSSIDs for batch inserts
			for ssid, ts := range d.ProbedSSIDs {
				allProbes = append(allProbes, ProbeModel{
					DeviceMAC: d.MAC,
					SSID:      ssid,
					LastSeen:  ts,
				})
			}
		}

		// Persist all ProbedSSIDs in one go
		if len(allProbes) > 0 {
			err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "device_mac"}, {Name: "ssid"}},
				DoUpdates: clause.AssignmentColumns([]string{"last_seen"}),
			}).Create(&allProbes).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetDevice retrieves a device by MAC.
func (a *SQLiteAdapter) GetDevice(ctx context.Context, mac string) (*domain.Device, error) {
	var model DeviceModel
	if err := a.db.WithContext(ctx).Preload("ProbedSSIDs").First(&model, "mac = ?", mac).Error; err != nil {
		return nil, err
	}

	return toDomain(model), nil
}

// GetAllDevices retrieves all devices.
func (a *SQLiteAdapter) GetAllDevices(ctx context.Context) ([]domain.Device, error) {
	var models []DeviceModel
	if err := a.db.WithContext(ctx).Preload("ProbedSSIDs").Find(&models).Error; err != nil {
		return nil, err
	}

	devices := make([]domain.Device, len(models))
	for i, m := range models {
		devices[i] = *toDomain(m)
	}
	return devices, nil
}

// GetDevicesByFilter retrieves devices matching the filter criteria
func (a *SQLiteAdapter) GetDevicesByFilter(ctx context.Context, filter domain.DeviceFilter) ([]domain.Device, error) {
	query := a.db.WithContext(ctx).Preload("ProbedSSIDs")

	// Apply filters dynamically
	if filter.Type != "" {
		query = query.Where("type = ?", filter.Type)
	}
	if filter.MinRSSI != 0 {
		query = query.Where("rssi >= ?", filter.MinRSSI)
	}
	if filter.Security != "" {
		query = query.Where("security = ?", filter.Security)
	}
	if filter.HasWPS != nil {
		if *filter.HasWPS {
			query = query.Where("wps_info != '' AND wps_info IS NOT NULL")
		} else {
			query = query.Where("wps_info = '' OR wps_info IS NULL")
		}
	}
	if !filter.SeenAfter.IsZero() {
		query = query.Where("last_seen >= ?", filter.SeenAfter)
	}
	if !filter.SeenBefore.IsZero() {
		query = query.Where("last_seen <= ?", filter.SeenBefore)
	}
	if filter.Vendor != "" {
		query = query.Where("vendor LIKE ?", "%"+filter.Vendor+"%")
	}
	if filter.SSID != "" {
		query = query.Where("ssid LIKE ?", "%"+filter.SSID+"%")
	}
	if filter.IsRandomized != nil {
		query = query.Where("is_randomized = ?", *filter.IsRandomized)
	}

	// Pagination
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	} else {
		// Default limit to 100 to prevent OOM if not specified
		// Users who want *all* must fetch mostly via batches or similar,
		// but providing a safe default is better for general usage.
		// If explicit "all" is needed, we might need a specific flag or convention (e.g. -1).
		// For now, let's stick to safe default.
		query = query.Limit(100)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	var models []DeviceModel
	if err := query.Find(&models).Error; err != nil {
		return nil, err
	}

	devices := make([]domain.Device, len(models))
	for i, m := range models {
		devices[i] = *toDomain(m)
	}
	return devices, nil
}

func (a *SQLiteAdapter) SaveProbe(ctx context.Context, mac string, ssid string) error {
	log.Printf("DEBUG SaveProbe: Called with MAC=%s SSID=%s", mac, ssid)
	probe := ProbeModel{
		DeviceMAC: mac,
		SSID:      ssid,
		LastSeen:  time.Now(),
	}
	err := a.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "device_mac"}, {Name: "ssid"}},
		DoUpdates: clause.AssignmentColumns([]string{"last_seen"}),
	}).Create(&probe).Error
	log.Printf("DEBUG SaveProbe: Upsert result - err=%v", err)
	return err
}

func (a *SQLiteAdapter) Close() error {
	sqlDB, err := a.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Helper toDomain removed as it's now in converter.go

// Ensure interface compliance
var _ ports.Storage = (*SQLiteAdapter)(nil)
