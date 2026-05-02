import type { DataSet } from 'vis-data';
import type { GraphData } from '../../types/graph';

import apIconUrl from '../../assets/icons/icon-ap.svg?url';
import stationIconUrl from '../../assets/icons/icon-station.svg?url';
import networkIconUrl from '../../assets/icons/icon-network.svg?url';

// ─── Handshake lock badge ─────────────────────────────────────────────────────

const LOCK_BADGE_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20">
  <circle cx="10" cy="10" r="9" fill="#10b981" opacity="0.92"/>
  <path d="M7 9V7.5a3 3 0 0 1 6 0V9" stroke="white" stroke-width="1.5" stroke-linecap="round" fill="none"/>
  <rect x="5.5" y="9" width="9" height="6.5" rx="1.5" fill="white"/>
  <circle cx="10" cy="12" r="1" fill="#10b981"/>
</svg>`;

const LOCK_BADGE_URL = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(LOCK_BADGE_SVG)}`;

// Cache so we don't re-draw on every sync tick
const apLockCache = new Map<string, string>();

function buildApLockImage(baseUrl: string, size: number): Promise<string> {
  const cacheKey = `${baseUrl}:${size}`;
  const cached = apLockCache.get(cacheKey);
  if (cached) return Promise.resolve(cached);

  return new Promise((resolve) => {
    const canvas = document.createElement('canvas');
    const px = size * 2; // retina
    canvas.width = px;
    canvas.height = px;
    const ctx = canvas.getContext('2d')!;

    const base = new Image();
    base.onload = () => {
      ctx.drawImage(base, 0, 0, px, px);

      const badgePx = Math.round(px * 0.42);
      const badge = new Image();
      badge.onload = () => {
        ctx.drawImage(badge, px - badgePx, px - badgePx, badgePx, badgePx);
        const dataUrl = canvas.toDataURL('image/png');
        apLockCache.set(cacheKey, dataUrl);
        resolve(dataUrl);
      };
      badge.onerror = () => resolve(baseUrl);
      badge.src = LOCK_BADGE_URL;
    };
    base.onerror = () => resolve(baseUrl);
    base.src = baseUrl;
  });
}

// ─── Constants ────────────────────────────────────────────────────────────────

// Distinct colors per node type — vivid so they're legible on dark bg
const NODE_COLORS: Record<string, { border: string; glow: string }> = {
  ap:      { border: '#22d3ee', glow: 'rgba(34, 211, 238, 0.55)' },   // cyan
  station: { border: '#a78bfa', glow: 'rgba(167, 139, 250, 0.55)' },  // violet
  network: { border: '#34d399', glow: 'rgba(52, 211, 153, 0.55)' },   // emerald
};

const NODE_SIZES: Record<string, number> = {
  ap: 22,
  station: 16,
  network: 28,
};

const ICON_URIS: Record<string, string> = {
  ap: apIconUrl,
  station: stationIconUrl,
  network: networkIconUrl,
};

// Edge colors by connection strength (RSSI-based)
const EDGE_RSSI_COLORS = {
  strong: { color: 'rgba(52, 211, 153, 0.85)',  width: 2.5 },  // green  ≥ -55 dBm
  fair:   { color: 'rgba(251, 191, 36, 0.75)',  width: 1.8 },  // amber  -55 to -70 dBm
  poor:   { color: 'rgba(248, 113, 113, 0.65)', width: 1.2 },  // red    < -70 dBm
  none:   { color: 'rgba(148, 163, 184, 0.30)', width: 0.8 },  // gray   no RSSI
};

const EDGE_TYPE_COLORS: Record<string, string> = {
  connection:  'rgba(34, 211, 238, 0.55)',
  probe:       'rgba(167, 139, 250, 0.50)',
  correlation: 'rgba(52, 211, 153, 0.45)',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function cleanLabel(label: string): string {
  return label
    .replace(/\s*\([0-9a-fA-F:]{17}\)/g, '')
    .replace(/\s*\(Randomized\)/g, '')
    .replace(/\s*\[.*?GHz\]/g, '')
    .trim();
}

function getNodeColorEntry(group: string): { border: string; glow: string } {
  return NODE_COLORS[group] ?? NODE_COLORS.ap;
}

function getEdgeStyle(rssi: number | undefined): { color: string; width: number } {
  if (rssi === undefined) return EDGE_RSSI_COLORS.none;
  if (rssi >= -55) return EDGE_RSSI_COLORS.strong;
  if (rssi >= -70) return EDGE_RSSI_COLORS.fair;
  return EDGE_RSSI_COLORS.poor;
}


// ─── Sync function (replaces the old React component) ────────────────────────

/** Returns true if new nodes or edges were added (signals caller to re-stabilize). */
export function syncGraphData(
  nodesDS: DataSet<any>,
  edgesDS: DataSet<any>,
  graphData: GraphData | null,
): boolean {
  if (!graphData) return false;

  const { nodes, edges } = graphData;

  const staleNodes = new Set<string>(nodesDS.getIds().map(String));
  const staleEdges = new Set<string>(edgesDS.getIds().map(String));

  let hasNewNodes = false;

  // 1. Add or update nodes
  nodes.forEach((node) => {
    const { border, glow } = getNodeColorEntry(node.group);
    const label = cleanLabel(node.label || node.ssid || node.mac || node.id);
    const size = NODE_SIZES[node.group] ?? NODE_SIZES.station;
    const baseImage = ICON_URIS[node.group] ?? ICON_URIS.station;

    const nodeId = String(node.id);
    const existing = nodesDS.get(nodeId);
    const colorObj = {
      border,
      background: glow,
      highlight: { border, background: glow },
      hover: { border, background: glow },
    };

    const hasLock = node.group === 'ap' && node.has_handshake;
    // Use cached lock image if already built, otherwise fall back to base while async build runs
    const cachedLock = hasLock ? apLockCache.get(`${baseImage}:${size}`) : undefined;
    const image = cachedLock ?? baseImage;

    if (!existing) {
      if (import.meta.env.DEV) console.debug(`[Graph] add node ${nodeId}`);
      nodesDS.add({
        id: nodeId,
        label,
        image,
        size,
        opacity: 1,
        color: colorObj,
        _meta: node,
      });
      hasNewNodes = true;
    } else {
      const imageChanged = existing.image !== image;
      const labelChanged = existing.label !== label;
      const rssiChanged = existing._meta?.rssi !== node.rssi;
      const lockChanged = (existing._meta?.has_handshake ?? false) !== (node.has_handshake ?? false);
      if (labelChanged || rssiChanged || lockChanged || imageChanged) {
        nodesDS.update({
          id: nodeId,
          label,
          image,
          size,
          color: colorObj,
          _meta: node,
        });
      }
    }

    // Async: build lock image and update node once ready (only if not cached yet)
    if (hasLock && !cachedLock) {
      buildApLockImage(baseImage, size).then((lockUrl) => {
        const current = nodesDS.get(nodeId);
        if (current && current._meta?.has_handshake) {
          nodesDS.update({ id: nodeId, image: lockUrl });
        }
      });
    }

    staleNodes.delete(nodeId);
  });

  // 2. Remove stale nodes
  staleNodes.forEach((id) => nodesDS.remove(id));

  let hasNewEdges = false;

  // 3. Add or update edges
  edges.forEach((edge) => {
    const rawEdgeId = edge.id || `${edge.from}-${edge.to}-${edge.type ?? 'connection'}`;
    const edgeId = String(rawEdgeId);

    const fromId = String(edge.from);
    const toId = String(edge.to);
    const fromNode = nodesDS.get(fromId);
    const toNode = nodesDS.get(toId);
    if (!fromNode || !toNode) return;

    // Derive RSSI from node metadata for strength-based coloring
    const rssi: number | undefined =
      fromNode._meta?.rssi ?? toNode._meta?.rssi ?? undefined;

    let edgeColor: string;
    let edgeWidth: number;

    if (edge.color) {
      edgeColor = edge.color;
      edgeWidth = 1.2;
    } else if (rssi !== undefined) {
      const style = getEdgeStyle(rssi);
      edgeColor = style.color;
      edgeWidth = style.width;
    } else {
      edgeColor = EDGE_TYPE_COLORS[edge.type ?? 'connection'] ?? EDGE_TYPE_COLORS.connection;
      edgeWidth = 1.0;
    }

    const existingEdge = edgesDS.get(edgeId);
    if (!existingEdge) {
      edgesDS.add({
        id: edgeId,
        from: fromId,
        to: toId,
        dashes: edge.dashed ?? false,
        color: { color: edgeColor, highlight: edgeColor, hover: edgeColor },
        width: edgeWidth,
        label: '',
        _meta: edge,
      });
      hasNewEdges = true;
    } else if (existingEdge._meta?.color !== edge.color || existingEdge._meta?.rssi !== rssi) {
      edgesDS.update({
        id: edgeId,
        color: { color: edgeColor, highlight: edgeColor, hover: edgeColor },
        width: edgeWidth,
        _meta: edge,
      });
    }

    staleEdges.delete(edgeId);
  });

  // 4. Remove stale edges
  staleEdges.forEach((id) => edgesDS.remove(id));

  return hasNewNodes || hasNewEdges;
}
