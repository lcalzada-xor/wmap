import React, { useEffect } from 'react';
import { useSigma } from '@react-sigma/core';
import type { GraphData, GraphNode, GraphEdge } from '../../types/graph';

// Import SVG icons as URLs natively handled by Vite
import apIconUrl from '../../assets/icons/icon-ap.svg';
import stationIconUrl from '../../assets/icons/icon-station.svg';
import networkIconUrl from '../../assets/icons/icon-network.svg';

interface GraphDataBridgeProps {
  graphData: GraphData | null;
}

// ─── Color helpers ───────────────────────────────────────────────────────────

const NODE_COLORS = {
  ap:      '#06b6d4',
  station: '#8b5cf6',
  network: '#10b981',
};

const NODE_SIZES = {
  ap:      20,
  station: 13,
  network: 24,
};

const ICON_URIS: Record<string, string> = {
  ap:      apIconUrl,
  station: stationIconUrl,
  network: networkIconUrl,
};


function getNodeColorByRSSI(
  group: string,
  rssi: number | undefined,
  config: GraphData['config']
): string {
  const baseColor = NODE_COLORS[group as keyof typeof NODE_COLORS] ?? '#06b6d4';

  if (rssi === undefined || !config) return baseColor;

  // Poor signal → use red
  if (rssi < config.rssi_thresholds.fair) return config.colors.poor;
  // Fair signal → keep type color but use fair color for border indicator
  if (rssi < config.rssi_thresholds.good) return config.colors.fair;

  return baseColor;
}

const EDGE_COLORS: Record<string, string> = {
  connection:  'rgba(6, 182, 212, 0.55)',
  probe:       'rgba(139, 92, 246, 0.45)',
  correlation: 'rgba(16, 185, 129, 0.5)',
};

// ─── Component ───────────────────────────────────────────────────────────────

export const GraphDataBridge: React.FC<GraphDataBridgeProps> = ({ graphData }) => {
  const sigma = useSigma();
  const graph = sigma.getGraph();

  useEffect(() => {
    if (!graphData) return;

    const { nodes, edges, config } = graphData;
    const currentNodes = new Set(graph.nodes());
    const currentEdges = new Set(graph.edges());

    // 1. Add or Update Nodes
    nodes.forEach((node: GraphNode) => {
      const group = node.group as keyof typeof NODE_COLORS;
      const nodeColor = getNodeColorByRSSI(node.group, node.rssi, config);
      const nodeSize = NODE_SIZES[group] ?? 13;
      const imageUri = ICON_URIS[node.group] ?? ICON_URIS['station'];

      if (!graph.hasNode(node.id)) {
        const x = Math.random() * 10 - 5;
        const y = Math.random() * 10 - 5;

        console.debug(`[Graph] Adding node: ${node.id} (${node.group})`, { image: !!imageUri });

        graph.addNode(node.id, {
          x,
          y,
          size: nodeSize,
          label: node.label || node.ssid || node.mac || node.id,
          color: nodeColor,
          type: 'image',
          image: imageUri,
          attributes: node,
        });
      } else {
        graph.mergeNodeAttributes(node.id, {
          color: nodeColor,
          size: nodeSize,
          label: node.label || node.ssid || node.mac || node.id,
          type: 'image',
          image: imageUri,
          attributes: node,
        });
      }

      currentNodes.delete(node.id);
    });

    // 2. Remove stale nodes
    currentNodes.forEach((nodeId) => {
      graph.dropNode(nodeId);
    });

    // 3. Add or Update Edges
    edges.forEach((edge: GraphEdge) => {
      // Create our logical edge id, which we will use as the graphology edge key
      const edgeId = `${edge.from}->${edge.to}`;

      if (graph.hasNode(edge.from) && graph.hasNode(edge.to)) {
        const edgeColor = edge.color
          || EDGE_COLORS[edge.type ?? 'connection']
          || 'rgba(99, 102, 241, 0.4)';

        if (!graph.hasEdge(edgeId)) {
          try {
            graph.addEdgeWithKey(edgeId, edge.from, edge.to, {
              id: edgeId,
              type: edge.dashed ? 'dashed' : 'line',
              color: edgeColor,
              size: edge.type === 'connection' ? 2 : 1,
              label: edge.label,
              attributes: edge,
            });
          } catch (e) {
            // Ignore if edge already exists or nodes are missing in a race condition
          }
        } else {
          try {
            graph.mergeEdgeAttributes(edgeId, {
              color: edgeColor,
            });
          } catch (e) {}
        }
        
        // Remove this explicitly keyed edge from the currentEdges set so it's not dropped
        currentEdges.delete(edgeId);
      }
    });

    // 4. Remove stale edges
    currentEdges.forEach((edgeId) => {
      try {
        graph.dropEdge(edgeId);
      } catch (e) {
        // ignoring errors if edge was already dropped when a node was dropped
      }
    });

  }, [graphData, graph, sigma]);

  return null;
};
