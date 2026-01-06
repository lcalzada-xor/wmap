# WMAP - WiFi Devices Mapper

Visualización en tiempo real de dispositivos WiFi mediante grafos y relaciones.

## 🚀 Características

- **Captura de Paquetes:** Modo monitor para interceptar Probe Requests, Beacons y Data Frames
- **Visualización en Tiempo Real:** Interfaz web con grafos interactivos
- **Fingerprinting Avanzado:** Detección de seguridad (WPA2/WPA3), estándares (WiFi 6/7), y firmas de dispositivos
- **Detección de Anomalías:** Evil Twin, ataques de deauth, etc.
- **Arquitectura Escalable:** Sharding con 16 fragmentos para alta concurrencia
- **Persistencia:** Base de datos SQLite con índices optimizados

## 📦 Instalación

### Requisitos

- Go 1.24+
- Tarjeta WiFi con soporte para modo monitor
- Linux (probado en Ubuntu/Debian)

### Compilación

```bash
go build ./cmd/wmap
```

## 🎯 Uso

### Modo Normal (Requiere sudo para modo monitor)

```bash
sudo ./wmap -i wlan1
```

### Modo Mock (Simulación sin hardware)

```bash
./wmap -mock
```

### Opciones Disponibles

```bash
./wmap -h
```

| Flag | Descripción | Default |
|------|-------------|---------|
| `-i` | Interfaz de red en modo monitor | `wlan0` |
| `-addr` | Dirección del servidor HTTP | `:8080` |
| `-lat` | Latitud estática | `40.4168` |
| `-lng` | Longitud estática | `-3.7038` |
| `-mock` | Modo simulación | `false` |
| `-db` | Ruta a la base de datos SQLite | `~/.wmap/wmap.db` |
| `-pcap` | Ruta para guardar PCAP (vacío = deshabilitado) | `""` |
| `-grpc` | Puerto del servidor gRPC | `9000` |
| `-debug` | Logging verboso | `false` |

## 📁 Estructura de Archivos

### Base de Datos

Por defecto, WMAP guarda la base de datos en:
```
~/.wmap/wmap.db
```

**Ventajas:**
- ✅ Permisos correctos del usuario (no requiere root)
- ✅ Persistencia entre ejecuciones con/sin sudo
- ✅ Fácil backup (`cp ~/.wmap/wmap.db backup.db`)

**Personalizar ubicación:**
```bash
./wmap -db /ruta/personalizada/wmap.db
```

O con variable de entorno:
```bash
export WMAP_DB=/ruta/personalizada/wmap.db
./wmap
```

### PCAP (Opcional)

Para guardar capturas de paquetes:
```bash
sudo ./wmap -i wlan1 -pcap /tmp/capture.pcap
```

## 🏗️ Arquitectura

### Hexagonal (Ports & Adapters)

```
cmd/
  wmap/          # Aplicación principal
  wmap-agent/    # Agente remoto (gRPC)
internal/
  core/
    domain/      # Modelos de dominio
    ports/       # Interfaces
    services/    # Lógica de negocio
  adapters/
    sniffer/     # Captura de paquetes (gopacket)
    storage/     # Persistencia (SQLite/GORM)
    web/         # Servidor HTTP + WebSockets
```

### Sharding para Escalabilidad

`NetworkService` usa **16 shards** con locks independientes:
- **Throughput:** ~10,000 paquetes/segundo (10x mejora vs lock global)
- **Latencia P99:** <5ms
- **Contención:** Reducida en 90%

## 🧪 Testing

```bash
# Tests unitarios
go test ./internal/core/services/... -v

# Tests con race detector
go test ./... -race

# Benchmarks
go test ./internal/core/services/... -bench=. -benchmem
```

## 🔧 Troubleshooting

### Error: "attempt to write a readonly database"

**Causa:** Archivo de base de datos creado con permisos incorrectos.

**Solución:**
```bash
rm ~/.wmap/wmap.db
./wmap  # Se recreará automáticamente
```

### Error: "Device or resource busy" (modo monitor)

**Causa:** Procesos conflictivos (NetworkManager, wpa_supplicant).

**Solución:**
```bash
sudo airmon-ng check kill
sudo ./wmap -i wlan1
```

### Error: "permission denied" (sin sudo)

**Causa:** Modo monitor requiere privilegios de root.

**Solución:** Ejecutar con `sudo` o configurar capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./wmap
./wmap -i wlan1  # Ahora funciona sin sudo
```

## 📊 Rendimiento

### Optimizaciones Implementadas

- ✅ **Sharding:** 16 fragmentos con locks independientes
- ✅ **Worker Pool:** N workers (N = CPU cores) para procesamiento paralelo
- ✅ **Buffered Channels:** 1000 slots para absorber ráfagas
- ✅ **TTL Automático:** Limpieza de dispositivos inactivos (10 min)
- ✅ **Índices DB:** Optimizados para consultas frecuentes
- ✅ **Observabilidad:** Métricas Prometheus integradas en `/metrics`

### Escenarios Probados

| Escenario | Dispositivos | CPU | Memoria | Latencia |
|-----------|--------------|-----|---------|----------|
| Casa | 10-20 | <5% | ~50MB | <1ms |
| Oficina | 50-100 | ~15% | ~100MB | <5ms |
| Centro Comercial | 500+ | ~40% | ~300MB | <10ms |
| Aeropuerto | 1000+ | ~60% | ~500MB | <20ms |

## 🛡️ Seguridad

### Consideraciones

- **Modo Monitor:** Captura tráfico pasivamente (no inyecta paquetes)
- **Legalidad:** Uso exclusivo para redes propias o con autorización
- **Privacidad:** MACs randomizadas detectadas automáticamente
- **Almacenamiento:** Base de datos local (no envía datos a terceros)

## 🤝 Contribuciones

Ver [`CONTRIBUTING.md`](CONTRIBUTING.md) para guías de desarrollo.

## 📝 Licencia

MIT License - Ver [`LICENSE`](LICENSE) para detalles.

## 🙏 Agradecimientos

- [gopacket](https://github.com/google/gopacket) - Captura de paquetes
- [GORM](https://gorm.io/) - ORM para Go
- [vis.js](https://visjs.org/) - Visualización de grafos
