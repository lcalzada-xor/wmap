import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import { Network, type Options } from 'vis-network';
import { DataSet } from 'vis-data';
import { NodeTooltip } from '../overlays/NodeTooltip';
import { NodeContextMenu } from '../overlays/NodeContextMenu';
import { ErrorBoundary } from '../common/ErrorBoundary';
import type { GraphData, GraphNode } from '../../types/graph';
import { syncGraphData } from './GraphDataBridge';

const VIS_OPTIONS: Options = {
  physics: {
    enabled: true,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {
      gravitationalConstant: -120,
      centralGravity: 0.01,
      springLength: 100,
      springConstant: 0.08,
      damping: 0.85,
      avoidOverlap: 1.0,
    },
    stabilization: { enabled: true, iterations: 200, updateInterval: 25, fit: true },
    minVelocity: 0.5,
    maxVelocity: 25,
    timestep: 0.3,
  },
  nodes: {
    shape: 'image',
    size: 18,
    borderWidth: 2,
    borderWidthSelected: 3,
    color: {
      border: 'rgba(255,255,255,0.15)',
      background: 'transparent',
      highlight: { border: '#ffffff', background: 'transparent' },
      hover: { border: '#ffffff', background: 'transparent' },
    },
    font: {
      face: 'Outfit, sans-serif',
      size: 11,
      color: '#e2e8f0',
      strokeWidth: 2,
      strokeColor: 'rgba(0,0,0,0.7)',
    },
    chosen: true,
  },
  edges: {
    width: 1,
    color: { inherit: false, opacity: 1 },
    smooth: { enabled: true, type: 'dynamic', roundness: 0.5 },
    arrows: { from: { enabled: true, scaleFactor: 0.4 } },
    selectionWidth: 2.5,
  },
  interaction: {
    hover: true,
    tooltipDelay: 0,
    hideEdgesOnDrag: true,
    dragNodes: true,
    zoomView: true,
    dragView: true,
  },
  layout: { improvedLayout: false },
};

interface ContextMenuState {
  node: GraphNode;
  x: number;
  y: number;
}

interface DeviceGraphProps {
  graphData: GraphData | null;
  onNodeClick?: (node: GraphNode) => void;
}

/** Collect all node IDs reachable from `startId` via any edge (BFS). */
function getConnectedSubgraph(startId: string, graphData: GraphData): Set<string> {
  const visited = new Set<string>([startId]);
  const queue = [startId];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const edge of graphData.edges) {
      let neighbor: string | null = null;
      if (edge.from === current && !visited.has(edge.to)) neighbor = edge.to;
      else if (edge.to === current && !visited.has(edge.from)) neighbor = edge.from;
      if (neighbor) {
        visited.add(neighbor);
        queue.push(neighbor);
      }
    }
  }
  return visited;
}

export const DeviceGraph: React.FC<DeviceGraphProps> = ({ graphData, onNodeClick }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const networkRef = useRef<Network | null>(null);
  const nodesRef = useRef(new DataSet<any>());
  const edgesRef = useRef(new DataSet<any>());
  const [hoverState, setHoverState] = useState<{ id: string; x: number; y: number } | null>(null);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [isolatedNodeId, setIsolatedNodeId] = useState<string | null>(null);
  const graphDataRef = useRef<GraphData | null>(null);
  const onNodeClickRef = useRef(onNodeClick);
  onNodeClickRef.current = onNodeClick;

  // Mount vis-network once
  useEffect(() => {
    if (!containerRef.current) return;

    const network = new Network(
      containerRef.current,
      { nodes: nodesRef.current, edges: edgesRef.current },
      VIS_OPTIONS,
    );

    networkRef.current = network;

    network.on('hoverNode', (params) => {
      const domPos = network.canvasToDOM({ x: params.pointer.canvas.x, y: params.pointer.canvas.y });
      setHoverState({ id: String(params.node), x: domPos.x, y: domPos.y });
      const canvas = containerRef.current?.querySelector('canvas') as HTMLCanvasElement | null;
      if (canvas) canvas.style.cursor = 'pointer';
    });

    network.on('blurNode', () => {
      setHoverState(null);
      const canvas = containerRef.current?.querySelector('canvas') as HTMLCanvasElement | null;
      if (canvas) canvas.style.cursor = 'default';
    });

    network.on('click', (params) => {
      if (params.nodes.length === 0) return;
      const id = String(params.nodes[0]);
      const node = graphDataRef.current?.nodes.find(n => n.id === id);
      if (node) onNodeClickRef.current?.(node);
    });

    // vis-network creates the canvas after Network() — wait one tick
    const attachContextMenu = () => {
      const canvas = containerRef.current?.querySelector('canvas');
      if (!canvas) return;
      const handleContextMenu = (e: MouseEvent) => {
        e.preventDefault();
        const nodeId = networkRef.current?.getNodeAt({ x: e.offsetX, y: e.offsetY });
        if (nodeId === undefined) {
          setContextMenu(null);
          return;
        }
        const node = graphDataRef.current?.nodes.find(n => n.id === String(nodeId));
        if (!node) return;
        setHoverState(null);
        setContextMenu({ node, x: e.clientX, y: e.clientY });
      };
      canvas.addEventListener('contextmenu', handleContextMenu);
      return () => canvas.removeEventListener('contextmenu', handleContextMenu);
    };

    let cleanup: (() => void) | undefined;
    const raf = requestAnimationFrame(() => { cleanup = attachContextMenu(); });

    return () => {
      cancelAnimationFrame(raf);
      cleanup?.();
      network.destroy();
      networkRef.current = null;
    };
  }, []);

  // Sync graph data, respecting isolation
  useEffect(() => {
    graphDataRef.current = graphData;
    if (!networkRef.current) return;

    if (isolatedNodeId && graphData) {
      const reachable = getConnectedSubgraph(isolatedNodeId, graphData);
      const isolated: GraphData = {
        ...graphData,
        nodes: graphData.nodes.filter(n => reachable.has(n.id)),
        edges: graphData.edges.filter(e => reachable.has(e.from) && reachable.has(e.to)),
      };
      syncGraphData(nodesRef.current, edgesRef.current, isolated);
    } else {
      syncGraphData(nodesRef.current, edgesRef.current, graphData);
    }
  }, [graphData, isolatedNodeId]);

  const handleContextAction = useCallback((action: string, node: GraphNode) => {
    switch (action) {
      case 'copy-mac': {
        const mac = node.mac ?? '';
        navigator.clipboard.writeText(mac).catch(() => {
          const ta = document.createElement('textarea');
          ta.value = mac;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
        });
        break;
      }
      case 'copy-ssid': {
        const ssid = node.ssid ?? '';
        navigator.clipboard.writeText(ssid).catch(() => {
          const ta = document.createElement('textarea');
          ta.value = ssid;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
        });
        break;
      }
      case 'focus': {
        networkRef.current?.focus(node.id, {
          scale: 1.4,
          animation: { duration: 400, easingFunction: 'easeInOutQuad' },
        });
        break;
      }
      case 'details': {
        onNodeClickRef.current?.(node);
        break;
      }
      case 'isolate': {
        setIsolatedNodeId(prev => (prev === node.id ? null : node.id));
        break;
      }
    }
  }, []);

  const hoveredNodeData = useMemo<GraphNode | null>(() => {
    if (!hoverState || !graphData) return null;
    return graphData.nodes.find(n => n.id === hoverState.id) ?? null;
  }, [hoverState, graphData]);

  return (
    <div className="graph-wrapper">
      {!graphData && (
        <div className="graph-loader" role="status" aria-live="polite">
          <div className="spinner" />
          <p>Awaiting network data...</p>
        </div>
      )}

      {isolatedNodeId && (
        <div className="graph-isolation-banner">
          <span>Isolation mode — showing connected subgraph</span>
          <button
            className="graph-isolation-clear"
            onClick={() => setIsolatedNodeId(null)}
          >
            Clear
          </button>
        </div>
      )}

      <ErrorBoundary>
        <div ref={containerRef} style={{ height: '100%', width: '100%', background: 'transparent' }} />
      </ErrorBoundary>

      {/* Zoom controls */}
      <div className="graph-controls">
        <button
          className="graph-control-btn"
          title="Zoom in"
          onClick={() => networkRef.current?.moveTo({ scale: (networkRef.current as any).getScale() * 1.3 })}
        >+</button>
        <button
          className="graph-control-btn"
          title="Zoom out"
          onClick={() => networkRef.current?.moveTo({ scale: (networkRef.current as any).getScale() * 0.77 })}
        >−</button>
        <button
          className="graph-control-btn"
          title="Fit view"
          onClick={() => networkRef.current?.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } })}
        >⊡</button>
      </div>

      <NodeTooltip
        node={hoveredNodeData}
        posX={hoverState?.x ?? null}
        posY={hoverState?.y ?? null}
      />

      {contextMenu && graphData && (
        <NodeContextMenu
          node={contextMenu.node}
          graphData={graphData}
          posX={contextMenu.x}
          posY={contextMenu.y}
          isolatedNodeId={isolatedNodeId}
          onAction={handleContextAction}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
};
