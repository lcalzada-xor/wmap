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
  // Define Si las necesitas en el futuro en front
}

export interface WPSDetails {
  // Define Si las necesitas en el futuro en front
}

export interface MobilityDomain {
  // Define Si las necesitas en el futuro en front
}

export interface RadioDetails {
  ssid?: string;
  security?: string;
  standard?: string;
  wps_info?: string;
  handshake_file?: string;
  capabilities?: string[];
  probedSSIDs?: string[];
  ieTags?: number[];
  
  rsn_info?: RSNInfo;
  wps_details?: WPSDetails;
  mobility_domain?: MobilityDomain;

  channel?: number;
  bw?: number; // channelWidth mapeado a bw
  frequency?: number;
  rssi?: number;

  is_wifi6?: boolean;
  is_wifi7?: boolean;
  is_randomized?: boolean;
  has_handshake?: boolean;
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
