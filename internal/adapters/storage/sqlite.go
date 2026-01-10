package storage

import (
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
	SSID           string
	Channel        int
	Crypto         string
	Security       string // WPA2, WPA3, OPEN, WEP
	Standard       string // 802.11ax (WiFi 6), etc.
	Frequency      int    // 2412, 5180, etc.
	ChannelWidth   int    // 20, 40, 80, 160 MHz
	WPSInfo        string // Configured, Unconfigured
	Latitude       float64
	Longitude      float64
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

	// Behavioral Data (Phase A)
	ProbeFrequency int64
	UniqueSSIDs    int
	AnomalyScore   float64
	ActiveHours    string // JSON encoded []int

	// ProbedSSIDs is a many-to-many or one-to-many relationship,
	// but for simplicity in SQLite we can store it in a separate table.
	ProbedSSIDs []ProbeModel `gorm:"foreignKey:DeviceMAC"`
}

// ProbeModel stores SSIDs probed by a device.
type ProbeModel struct {
	ID        uint   `gorm:"primaryKey"`
	DeviceMAC string `gorm:"index"`
	SSID      string
	LastSeen  time.Time
}

// NewSQLiteAdapter initializes the database and migrates schema.
func NewSQLiteAdapter(path string) (*SQLiteAdapter, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	// Auto Migrate
	if err := db.AutoMigrate(&DeviceModel{}, &ProbeModel{}, &domain.User{}, &domain.AuditLog{}); err != nil {
		return nil, err
	}

	// Create Indices for Performance
	db.Exec("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON device_models(last_seen)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_devices_type ON device_models(type)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_devices_ssid ON device_models(ssid)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_probes_ssid ON probe_models(ssid)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_devices_security ON device_models(security)")

	return &SQLiteAdapter{db: db}, nil
}

// SaveDevice saves or updates a device and its probes.
func (a *SQLiteAdapter) SaveDevice(d domain.Device) error {
	// Convert domain.Device to DeviceModel
	// Convert domain.Device to DeviceModel
	model := toModel(d)

	// Upsert Device
	// On conflict (MAC), update all fields.
	if err := a.db.Save(&model).Error; err != nil {
		return err
	}
	// Save Probed SSIDs
	for ssid, ts := range d.ProbedSSIDs {
		// Use FirstOrCreate to avoid duplicates, update timestamp if exists
		var probe ProbeModel
		if err := a.db.Where(&ProbeModel{DeviceMAC: d.MAC, SSID: ssid}).First(&probe).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				// Create new
				probe = ProbeModel{
					DeviceMAC: d.MAC,
					SSID:      ssid,
					LastSeen:  ts,
				}
				if err := a.db.Create(&probe).Error; err != nil {
					log.Printf("Failed to save probe: %v", err)
				}
			}
		} else {
			// Update existing timestamp
			probe.LastSeen = ts
			a.db.Save(&probe)
		}
	}

	return nil
}

// SaveDevicesBatch saves multiple devices in a single transaction.
func (a *SQLiteAdapter) SaveDevicesBatch(devices []domain.Device) error {
	if len(devices) == 0 {
		return nil
	}

	models := make([]DeviceModel, len(devices))
	for i, d := range devices {
		models[i] = toModel(d)
	}

	return a.db.Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).CreateInBatches(models, 100).Error
	})
}

// GetDevice retrieves a device by MAC.
func (a *SQLiteAdapter) GetDevice(mac string) (*domain.Device, error) {
	var model DeviceModel
	if err := a.db.Preload("ProbedSSIDs").First(&model, "mac = ?", mac).Error; err != nil {
		return nil, err
	}
	return toDomain(model), nil
}

// GetAllDevices retrieves all devices.
func (a *SQLiteAdapter) GetAllDevices() ([]domain.Device, error) {
	var models []DeviceModel
	if err := a.db.Preload("ProbedSSIDs").Find(&models).Error; err != nil {
		return nil, err
	}

	devices := make([]domain.Device, len(models))
	for i, m := range models {
		devices[i] = *toDomain(m)
	}
	return devices, nil
}

// GetDevicesByFilter retrieves devices matching the filter criteria
func (a *SQLiteAdapter) GetDevicesByFilter(filter domain.DeviceFilter) ([]domain.Device, error) {
	query := a.db.Preload("ProbedSSIDs")

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

func (a *SQLiteAdapter) SaveProbe(mac string, ssid string) error {
	return nil
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
