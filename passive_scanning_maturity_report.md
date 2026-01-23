# Informe de Madurez: Búsqueda Pasiva de Vulnerabilidades en WMAP

## 1. Resumen Ejecutivo

El sistema de análisis pasivo de vulnerabilidades de `wmap` presenta un nivel de **madurez media-alta**. La arquitectura base es sólida, modular y extensible, superando a herramientas básicas de escaneo al incorporar análisis profundo de Elementos de Información (IEs) y detección de anomalías comportamentales.

El motor de parseo (`PacketHandler` + `ie` parsers) es capaz de extraer metadatos críticos (RSN, WPS, Vendor), lo que permite detectar con precisión vulnerabilidades de protocolo y configuración sin necesidad de enviar paquetes (sigilo total). Sin embargo, existen oportunidades claras para evolucionar hacia un sistema de "Inteligencia de Señales" (SIGINT) más avanzado.

## 2. Análisis del Estado Actual

### Puntos Fuertes (Fortalezas)
*   **Parseo Profundo de Protocolos (RSN/WPS)**: La implementación en `rsn.go` y `wps.go` es exhaustiva. Identifica correctamente suites de cifrado modernas (SAE/WPA3, OWE) y legadas (WEP, TKIP), así como estados de configuración WPS granulares.
*   **Detección Híbrida**: Combina detección basada en firmas (Vendor DB) con detección basada en heurísticas (Retry Rate, Karma, Evil Twin).
*   **Arquitectura Modular**: La separación entre `PacketHandler` (ingesta), `DeviceRegistry` (estado) y `VulnerabilityDetector` (lógica) facilita la incorporación de nuevos detectores sin refactorizar el núcleo.
*   **Enfoque en Privacidad**: Módulos específicos para detectar fugas de información en clientes (Probe Leakage, fallos en aleatorización MAC).

### Limitaciones Actuales
*   **Análisis Stateless (Sin Estado)**: Gran parte de la detección se basa en el estado actual del dispositivo o paquetes individuales. Falta correlación temporal avanzada (ej. análisis de secuencias para fingerprinting de reloj).
*   **Base de Datos Estática**: La `VendorDatabase` depende de archivos JSON estáticos. No hay integración con feeds de vulnerabilidades (CVEs) en tiempo real o bases de datos dinámicas de patrones de contraseñas.
*   **Fingerprinting Limitado**: El fingerprinting de SO parece depender de IEs básicos. Se desaprovecha información rica presente en tramas de datos (patterns de tamaño de paquete, timings) y frames de control.

## 3. Hoja de Ruta de Mejoras

### Corto Plazo: Refinamiento y Precisión (1-3 meses)

El objetivo es maximizar el valor de la información que ya se está capturando.

1.  **Detección de "Direct Probe Response" (Karma Avanzado)**:
    *   *Mejora*: Detectar APs que responden a *cualquier* Probe Request, no solo contar SSIDs probados por clientes.
    *   *Implementación*: Correlacionar Probe Req (Client) con Probe Resp (AP) y verificar si el AP cambia su SSID dinámicamente.

2.  **Inferencia de Fast Roaming Inseguro (802.11r)**:
    *   *Mejora*: Analizar el Mobility Domain IE (MDIE) para verificar si se usa SHA-1 o cifrados débiles en el intercambio FT.
    *   *Ventaja*: Identificar redes corporativas mal configuradas pasivamente.

3.  **Análisis de Handshake Parcial**:
    *   *Mejora*: Incluso sin capturar el handshake completo (4-way), analizar el mensaje M1 del AP para validar la robustez del PRF y la entropía del Nonce (detección de generadores de números aleatorios débiles, como el fallo de "Nonce Reuse").

### Medio Plazo: Análisis Comportamental y Series Temporales (3-6 meses)

Introducir el factor "tiempo" y "contexto" en el análisis.

1.  **Huella Digital de Reloj (Clock Skew)**:
    *   *Mejora*: Analizar los campos `Timestamp` de los Beacons a lo largo del tiempo.
    *   *Uso*: Detectar "Fake APs" o Evil Twins de alta calidad. El hardware del atacante tendrá una deriva de reloj (skew) diferente al AP legítimo.

2.  **Detección de Deauth Floods Inteligentes**:
    *   *Mejora*: Ir más allá de la detección básica de tramas de Deauth. Analizar patrones de "Pulse interval" para diferenciar herramientas automáticas (ej. aireplay-ng) de interferencias legítimas o Roaming agresivo.

3.  **Análisis de Tráfico Cifrado (Pattern of Life)**:
    *   *Mejora*: Sin descifrar, clasificar el tipo de tráfico (Streaming, VoIP, Idle) basándose en tamaño de paquetes y tiempos de llegada.
    *   *Uso*: Detectar cámaras de seguridad Wi-Fi ocultas (tráfico constante de subida UDP) o dispositivos IoT vulnerables.

### Largo Plazo: Inteligencia y Escalabilidad (6-12 meses)

Transformar la herramienta en una plataforma de monitoreo distribuido.

1.  **Arquitectura de Sensores Distribuidos**:
    *   *Visión*: Desacoplar el `Sniffer` del `Core`. Permitir que múltiples sondas (Raspberry Pis, etc.) envíen metadatos (formato Protobuf/gRPC) a un cerebro central.
    *   *Ventaja*: Triangulación pasiva real y monitoreo de grandes superficies.

2.  **Modelos de ML en el Edge**:
    *   *Visión*: Entrenar modelos ligeros (TensorFlow Lite) para clasificación de dispositivos e intrusiones, reemplazando reglas estáticas (`if rate > 0.2`).
    *   *Ventaja*: Adaptabilidad a entornos ruidosos y reducción de falsos positivos en la detección de anomalías.

3.  **Integración CVE Dinámica**:
    *   *Visión*: Vincular el Fingerprinting de Versión/Modelo detectado pasivamente con una base de datos CVE local consultable.
    *   *Ventaja*: Reportar "Posible CVE-202X-XXXX" solo escuchando un Beacon.

## 4. Conclusión

`wmap` tiene una base excelente para la vigilancia pasiva. La inversión inmediata debe ir a **profundizar en el análisis de IEs de gestión (802.11k/v/r)** y mejorar el **fingerprinting de dispositivos**, ya que esto ofrece el mayor retorno de inversión en "visibilidad" sin requerir cambios arquitectónicos masivos.
