# Contribuir a WMAP

¡Gracias por tu interés en contribuir a WMAP! Este documento proporciona guías para el desarrollo.

## 🚀 Configuración del Entorno

### Requisitos

- Go 1.24+
- Tarjeta WiFi con soporte para modo monitor (para testing real)
- Git

### Clonar el Repositorio

```bash
git clone https://github.com/lcalzada-xor/wmap.git
cd wmap
```

### Instalar Dependencias

```bash
go mod download
```

### Compilar

```bash
go build ./cmd/wmap
```

## 🧪 Testing

### Ejecutar Tests

```bash
# Tests unitarios
go test ./... -v

# Tests con race detector
go test ./... -race

# Tests de cobertura
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Benchmarks

```bash
go test ./internal/core/services/... -bench=. -benchmem
```

### Modo Mock

Para desarrollo sin hardware WiFi:

```bash
./wmap -mock
```

## 📝 Estilo de Código

### Convenciones

- Seguir las [Effective Go guidelines](https://golang.org/doc/effective_go)
- Usar `gofmt` para formatear código
- Ejecutar `go vet` antes de commit
- Mantener cobertura de tests > 80%

### Linting

```bash
# Instalar golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Ejecutar linter
golangci-lint run
```

## 🏗️ Arquitectura

WMAP sigue arquitectura hexagonal (Ports & Adapters):

```
internal/
  core/
    domain/      # Modelos de dominio (sin dependencias externas)
    ports/       # Interfaces (contratos)
    services/    # Lógica de negocio
  adapters/
    sniffer/     # Captura de paquetes
    storage/     # Persistencia
    web/         # HTTP + WebSockets
```

### Principios

- **Independencia de frameworks**: El core no depende de librerías externas
- **Testabilidad**: Todas las dependencias son inyectadas
- **Separación de concerns**: Cada capa tiene responsabilidades claras

## 🔄 Workflow de Contribución

### 1. Fork y Branch

```bash
git checkout -b feature/mi-nueva-funcionalidad
```

### 2. Desarrollar

- Escribir tests primero (TDD)
- Implementar funcionalidad
- Asegurar que todos los tests pasan

### 3. Commit

Usar mensajes descriptivos:

```bash
git commit -m "feat: añadir detección de WiFi 7"
git commit -m "fix: corregir race condition en NetworkService"
git commit -m "docs: actualizar README con nuevas opciones"
```

Formato de commits (opcional pero recomendado):
- `feat:` Nueva funcionalidad
- `fix:` Corrección de bug
- `docs:` Cambios en documentación
- `test:` Añadir o modificar tests
- `refactor:` Refactorización de código
- `perf:` Mejoras de rendimiento

### 4. Push y Pull Request

```bash
git push origin feature/mi-nueva-funcionalidad
```

Crear Pull Request en GitHub con:
- Descripción clara de los cambios
- Referencias a issues relacionados
- Screenshots si aplica (cambios UI)

## 🐛 Reportar Bugs

Usar GitHub Issues con:

- **Título descriptivo**
- **Pasos para reproducir**
- **Comportamiento esperado vs actual**
- **Versión de Go y OS**
- **Logs relevantes**

## 💡 Proponer Funcionalidades

Abrir un Issue de tipo "Feature Request" con:

- **Descripción del problema** que resuelve
- **Solución propuesta**
- **Alternativas consideradas**
- **Impacto en rendimiento/compatibilidad**

## 📚 Áreas de Contribución

### Backend

- Nuevos protocolos WiFi (WiFi 7, 802.11be)
- Detección de ataques avanzados
- Optimizaciones de rendimiento
- Integración con hardware GPS

### Frontend

- Mejoras en visualización de grafos
- Nuevos filtros y búsquedas
- Dashboard de métricas
- Exportación de reportes

### Infraestructura

- CI/CD pipelines
- Docker/Kubernetes deployment
- Documentación
- Tests de integración

## 🛡️ Seguridad

Para reportar vulnerabilidades de seguridad, **NO** usar Issues públicos. Contactar directamente al mantenedor.

## 📄 Licencia

Al contribuir, aceptas que tus contribuciones se licencien bajo MIT License.

## 🙏 Agradecimientos

¡Toda contribución es valiosa! Desde reportar bugs hasta implementar features complejas.
