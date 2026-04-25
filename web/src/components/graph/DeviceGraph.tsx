import React, { useEffect, useState } from 'react';
import {
  SigmaContainer,
  ControlsContainer,
  ZoomControl,
  FullScreenControl,
  useRegisterEvents,
  useSigma,
} from '@react-sigma/core';
import { useWorkerLayoutForceAtlas2 } from '@react-sigma/layout-forceatlas2';
import { createNodeImageProgram } from '@sigma/node-image';
import '@react-sigma/core/lib/style.css';

import { GraphDataBridge } from './GraphDataBridge';
import { NodeTooltip } from '../overlays/NodeTooltip';
import { ErrorBoundary } from '../common/ErrorBoundary';
import type { GraphData, GraphNode } from '../../types/graph';

// ─── ForceAtlas2 Layout ──────────────────────────────────────────────────────

const FA2_SETTINGS = {
  gravity: 0.8,
  scalingRatio: 10,
  slowDown: 10,
  adjustSizes: true,
};

const ForceAtlas2Layout: React.FC = () => {
  const sigma = useSigma();
  const { start, kill } = useWorkerLayoutForceAtlas2({
    settings: FA2_SETTINGS,
  });

  const [hasNodes, setHasNodes] = useState(false);

  useEffect(() => {
    const graph = sigma.getGraph();
    const checkNodes = () => {
      if (graph.order > 0) {
        setHasNodes(true);
        return true;
      }
      return false;
    };

    if (checkNodes()) return;

    const id = setInterval(checkNodes, 500);
    return () => clearInterval(id);
  }, [sigma]);

  useEffect(() => {
    if (!hasNodes) return;
    try {
      start();
    } catch (e) {
      console.error('FA2 Start Error:', e);
    }
    return () => {
      try {
        kill();
      } catch (e) {}
    };
  }, [hasNodes, start, kill]);

  return null;
};

// ─── Graph Events ────────────────────────────────────────────────────────────

const GraphEvents: React.FC<{ setHoveredNode: (node: string | null) => void }> = ({
  setHoveredNode,
}) => {
  const registerEvents = useRegisterEvents();
  const sigma = useSigma();
  const [draggedNode, setDraggedNode] = useState<string | null>(null);

  useEffect(() => {
    registerEvents({
      enterNode: (event) => setHoveredNode(event.node),
      leaveNode: () => setHoveredNode(null),
      downNode: (e) => {
        setDraggedNode(e.node);
        sigma.getGraph().setNodeAttribute(e.node, 'highlighted', true);
      },
      mousemovebody: (e) => {
        if (!draggedNode) return;
        const pos = sigma.viewportToGraph(e);
        sigma.getGraph().setNodeAttribute(draggedNode, 'x', pos.x);
        sigma.getGraph().setNodeAttribute(draggedNode, 'y', pos.y);
        e.original.preventDefault();
        e.original.stopPropagation();
      },
      mouseup: () => {
        if (draggedNode) {
          setDraggedNode(null);
          sigma.getGraph().removeNodeAttribute(draggedNode, 'highlighted');
        }
      },
      mousedown: () => {
        if (!sigma.getCustomBBox()) sigma.setCustomBBox(sigma.getBBox());
      },
    });
  }, [registerEvents, setHoveredNode, draggedNode, sigma]);

  return null;
};

// ─── Constants ───────────────────────────────────────────────────────────────

const SIGMA_STYLE = {
  height: '100%',
  width: '100%',
  background: 'transparent',
} as const;

const SIGMA_SETTINGS = {
  allowInvalidContainer: true,
  nodeProgramClasses: {
    image: createNodeImageProgram({
      padding: 0.15,
      colorAttribute: 'color', // Use node color for the circle background
      keepWithinCircle: true,
    }),
  },
  defaultNodeType: 'image',
  labelFont: 'Outfit, sans-serif',
  labelWeight: '600',
  labelColor: { color: '#ffffff' },
  labelSize: 12,
  renderLabels: true,
  zIndex: true,
  labelRenderedSizeThreshold: 0,
};

interface DeviceGraphProps {
  graphData: GraphData | null;
}

export const DeviceGraph: React.FC<DeviceGraphProps> = ({ graphData }) => {
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hoveredNodeData, setHoveredNodeData] = useState<GraphNode | null>(null);

  useEffect(() => {
    if (hoveredNodeId && graphData) {
      const nodeData = graphData.nodes.find((n) => n.id === hoveredNodeId);
      setHoveredNodeData(nodeData || null);
    } else {
      setHoveredNodeData(null);
    }
  }, [hoveredNodeId, graphData]);

  return (
    <div className="graph-container" style={{ width: '100%', height: '100%', position: 'relative' }}>
      <ErrorBoundary>
        <SigmaContainer
          style={SIGMA_STYLE}
          settings={SIGMA_SETTINGS}
        >
          <GraphDataBridge graphData={graphData} />
          <ForceAtlas2Layout />
          <GraphEvents setHoveredNode={setHoveredNodeId} />

          <ControlsContainer position="bottom-right">
            <ZoomControl />
            <FullScreenControl />
          </ControlsContainer>
        </SigmaContainer>
      </ErrorBoundary>

      <NodeTooltip node={hoveredNodeData} />

      <style>{`
        @keyframes tooltipFadeIn {
          from { opacity: 0; transform: translateY(6px) scale(0.97); }
          to   { opacity: 1; transform: translateY(0)   scale(1); }
        }
      `}</style>
    </div>
  );
};
