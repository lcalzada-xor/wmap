import React, { useEffect, useRef } from 'react';
import type { GraphNode, GraphData } from '../../types/graph';
import { getTypeColor } from '../../utils/nodeUtils';
import './NodeContextMenu.css';

export interface ContextMenuAction {
  id: string;
  label: string;
  icon: string;
  danger?: boolean;
  disabled?: boolean;
}

interface NodeContextMenuProps {
  node: GraphNode;
  graphData: GraphData;
  posX: number;
  posY: number;
  isolatedNodeId: string | null;
  onAction: (action: string, node: GraphNode) => void;
  onClose: () => void;
}

export const NodeContextMenu: React.FC<NodeContextMenuProps> = ({
  node,
  graphData,
  posX,
  posY,
  isolatedNodeId,
  onAction,
  onClose,
}) => {
  const menuRef = useRef<HTMLDivElement>(null);
  const typeColor = getTypeColor(node.group);
  const isIsolated = isolatedNodeId === node.id;

  const connectedCount = graphData.edges.filter(
    e => e.from === node.id || e.to === node.id,
  ).length;

  const actions: ContextMenuAction[] = [
    {
      id: 'copy-mac',
      label: 'Copy MAC Address',
      icon: '⎘',
      disabled: !node.mac,
    },
    {
      id: 'copy-ssid',
      label: 'Copy SSID',
      icon: '⎘',
      disabled: !node.ssid,
    },
    {
      id: 'focus',
      label: 'Center on Node',
      icon: '◎',
    },
    {
      id: 'details',
      label: 'Open Details Panel',
      icon: '▤',
    },
    {
      id: 'isolate',
      label: isIsolated ? 'Clear Isolation' : `Isolate Node (${connectedCount} links)`,
      icon: isIsolated ? '⊞' : '⊟',
      danger: isIsolated,
    },
  ].filter(a => !a.disabled);

  // Close on outside click or Escape
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [onClose]);

  // Constrain to viewport
  const menuWidth = 210;
  const menuHeight = actions.length * 36 + 52;
  const left = posX + menuWidth > window.innerWidth - 8 ? posX - menuWidth : posX;
  const top = posY + menuHeight > window.innerHeight - 8 ? posY - menuHeight : posY;

  return (
    <div
      ref={menuRef}
      className="node-context-menu"
      style={{
        left,
        top,
        '--type-color': typeColor,
        '--type-color-alpha': `${typeColor}33`,
      } as React.CSSProperties}
      onContextMenu={e => e.preventDefault()}
    >
      <div className="ncm-header">
        <span className="ncm-header-label">
          {node.ssid || node.label || node.mac || node.id}
        </span>
        <span className="ncm-header-type">
          {node.group === 'ap' ? 'AP' : node.group === 'station' ? 'STA' : 'NET'}
        </span>
      </div>

      <div className="ncm-divider" />

      <div className="ncm-actions">
        {actions.map(action => (
          <button
            key={action.id}
            className={`ncm-action${action.danger ? ' danger' : ''}`}
            onClick={() => {
              onAction(action.id, node);
              onClose();
            }}
          >
            <span className="ncm-action-icon">{action.icon}</span>
            <span className="ncm-action-label">{action.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
};
