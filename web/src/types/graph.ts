export type GraphGroup = 'ap' | 'station' | 'network';

export interface RSSIThresholds {
  good: number;
  fair: number;
}

export interface GraphColors {
  good: string;
  fair: string;
  poor: string;
  auth_failed: string;
}

export interface GraphConfig {
  rssi_thresholds: RSSIThresholds;
  colors: GraphColors;
}

export interface NodeIdentity {
  id: string;
  label: string;
  group: GraphGroup;
  mac?: string;
  vendor?: string;
  signature?: string;
  model?: string;
  os?: string;
  first_seen?: string; // ISO DateTime
  last_seen?: string; // ISO DateTime
}

export interface RSNInfo {
  // TODO: define fields when needed in the frontend
  [key: string]: unknown;
}

export interface WPSDetails {
  // TODO: define fields when needed in the frontend
  [key: string]: unknown;
}

export interface MobilityDomain {
  // TODO: define fields when needed in the frontend
  [key: string]: unknown;
}

export interface BSSLoad {
  station_count: number;
  channel_utilization: number; // 0-255 → 0-100%
  available_admission: number;
}

export interface RadioDetails {
  ssid?: string;
  security?: string;
  crypto?: string;
  standard?: string;
  wps_info?: string;
  handshake_file?: string;
  last_anonce?: string;
  capabilities?: string[];
  probedSSIDs?: string[];
  observed_ssids?: string[];
  ieTags?: number[];

  rsn_info?: RSNInfo;
  wps_details?: WPSDetails;
  mobility_domain?: MobilityDomain;
  bss_load?: BSSLoad;

  channel?: number;
  bw?: number;
  frequency?: number;
  rssi?: number;

  is_wifi6?: boolean;
  is_wifi7?: boolean;
  is_randomized?: boolean;
  has_handshake?: boolean;
  has11k?: boolean;
  has11v?: boolean;
  has11r?: boolean;
}

export interface TrafficStats {
  data_tx: number;
  data_rx: number;
  packets: number;
  retries: number;
}

export type ConnectionState = string;

export interface ConnectionDetails {
  connection_state?: ConnectionState;
  connection_target?: string;
  connection_error?: string;
}

export interface GraphNode extends NodeIdentity, RadioDetails, TrafficStats, ConnectionDetails {
  is_stale?: boolean;
}

export type EdgeType = 'connection' | 'probe' | 'correlation';

export interface GraphEdge {
  id?: string;
  from: string;
  to: string;
  dashed?: boolean;
  type?: EdgeType;
  label?: string;
  color?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  config?: GraphConfig;
}

export interface WSGraphMessage {
  type: 'graph';
  payload: GraphData;
}

export function isWSGraphMessage(msg: unknown): msg is WSGraphMessage {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as WSGraphMessage).type === 'graph' &&
    typeof (msg as WSGraphMessage).payload === 'object'
  );
}

export type AlertSeverity = 'info' | 'warning' | 'error' | 'critical';
export type AlertType = 'anomaly' | 'ssid_match' | 'mac_match' | 'HANDSHAKE_CAPTURED' | 'ANOMALY';

export type AlertSubtype =
  | 'DEAUTH_DETECTED'
  | 'BROADCAST_DEAUTH'
  | 'HIGH_RETRY_RATE'
  | 'KARMA_DETECTION'
  | 'EVIL_TWIN_DETECTED'
  | 'OUI_SPOOFING'
  | 'KARMA_AP_DETECTED'
  | 'RULE_MATCH'
  | 'WPA_HANDSHAKE'
  | 'VULNERABILITY_DETECTED'
  | 'WEAK_CRYPTO_ZERO_NONCE'
  | 'WEAK_CRYPTO_BAD_RNG'
  | (string & {});

export interface Alert {
  id: string;
  type: AlertType;
  message: string;
  // Backend sends capitalized ("Low","Medium","High","Critical") — normalize on ingest
  severity: string;
  timestamp: string;
  device_mac?: string;
  subtype?: AlertSubtype;
  target_mac?: string;
  details?: string;
  rule_id?: string;
  handshake_file?: string;
}

export interface WSAlertMessage {
  type: 'alert';
  payload: Alert;
}

export interface WSLogMessage {
  type: 'log';
  payload: { message: string; level: string };
}

export function isWSAlertMessage(msg: unknown): msg is WSAlertMessage {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as WSAlertMessage).type === 'alert' &&
    typeof (msg as WSAlertMessage).payload === 'object'
  );
}

export function isWSLogMessage(msg: unknown): msg is WSLogMessage {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as WSLogMessage).type === 'log' &&
    typeof (msg as WSLogMessage).payload === 'object'
  );
}
